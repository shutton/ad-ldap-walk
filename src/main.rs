use crate::util::*;
use anyhow::{anyhow, Result};
use itertools::Itertools;
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use log::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::io::AsyncWriteExt;

const MAX_QUERY_USERS: usize = 128;

mod util;

#[derive(Debug, StructOpt)]
/// Walk an LDAP server to discern reporting structure
struct CmdlineOpts {
    /// ID to bind with
    #[structopt(short = "u", long)]
    bind_user: String,

    /// LDAP server
    #[structopt(short = "s", long)]
    server: String,

    /// LDAP search base
    #[structopt(short = "b", long)]
    search_base: String,

    /// Where to save captures
    #[structopt(short = "d", long)]
    state_dir: Option<String>,
    root_users: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct SavedState {
    /**
     * A given employee's manager
     */
    emp_manager: BTreeMap<String, String>,
    /**
     * A given manager's employees
     */
    manager_reports: BTreeMap<String, Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cmdline = CmdlineOpts::from_args();

    #[cfg(target_os = "macos")]
    let (password, set_new_password) = loop {
        use security_framework::os::macos::keychain::SecKeychain;
        let mut keychain = SecKeychain::default()?;
        keychain.unlock(None)?;
        info!(
            "Querying macOS Keychain for {}/{}",
            cmdline.server, &cmdline.bind_user
        );
        match keychain.find_generic_password(&cmdline.server, &cmdline.bind_user) {
            Err(e) => match &e.code() {
                -25300 => {
                    break (
                        rpassword::read_password_from_tty(Some(
                            format!("Enter password for {}: ", cmdline.server).as_str(),
                        ))?,
                        true,
                    );
                }
                code => {
                    panic!("Error code={} message={:?}", code, e.message());
                }
            },
            Ok((password, _)) => break (String::from_utf8(password.as_ref().to_vec())?, false),
        }
    };

    let (conn, mut ldap) =
        LdapConnAsync::new(format!("ldap://{}", cmdline.server).as_ref()).await?;

    // This thing just sits in the background
    let _cxnhandle = tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            warn!("LDAP connection error: {}", e);
        }
    });

    ldap.simple_bind(&cmdline.bind_user, &password).await?;
    if cmdline.root_users.is_empty() {
        return Err(anyhow!("root user(s) not specified"));
    }

    let state_dir = PathBuf::from(
        &cmdline
            .state_dir
            .unwrap_or_else(|| format!("{}/.ldap-walk/", std::env::var("HOME").unwrap())),
    );
    let mut people_dir = state_dir.clone();
    people_dir.push("people");
    std::fs::create_dir_all(&state_dir)
        .map_err(|e| anyhow!("Unable to create directory ({:?}): {}", state_dir, e))?;
    // Do this in a separate operation just to make for a better error message
    std::fs::create_dir_all(&people_dir)
        .map_err(|e| anyhow!("Unable to create directory ({:?}): {}", people_dir, e))?;

    for root_user in cmdline.root_users {
        build_trees(&state_dir, &root_user, &mut ldap, &cmdline.search_base).await?;
    }
    #[cfg(target_os = "macos")]
    if set_new_password {
        info!(
            "Saving password for {}/{} to keychain",
            &cmdline.server, &cmdline.bind_user
        );
        use security_framework::os::macos::keychain::SecKeychain;
        let mut keychain = SecKeychain::default()?;
        keychain.unlock(None)?;
        keychain.set_generic_password(&cmdline.server, &cmdline.bind_user, password.as_bytes())?;
    }

    Ok(())
}

async fn build_trees(
    state_dir: &PathBuf,
    root_user: &str,
    ldap: &mut Ldap,
    search_base: &str,
) -> Result<()> {
    let mut state_filepath = state_dir.clone();
    state_filepath.push(format!("{}.json", root_user));
    let mut dump_filepath = state_dir.clone();
    dump_filepath.push(format!("{}-hier.txt", root_user));
    let mut dump_filepath_tmp = state_dir.clone();
    dump_filepath_tmp.push(format!(".{}-hier.txt.tmp", root_user));
    let mut hier_fh = tokio::fs::File::create(&dump_filepath_tmp).await?;

    let emp_manager: BTreeMap<String, String> = BTreeMap::new();
    let manager_reports: BTreeMap<String, Vec<String>> = BTreeMap::new();

    let mut cur_state = SavedState {
        emp_manager,
        manager_reports,
    };

    // Seed the tree the root user
    let mut remaining = VecDeque::new();
    remaining.push_back(root_user.to_owned());

    let mut n_queries: i32 = 0;
    while !remaining.is_empty() {
        let query_str = build_query(&mut remaining);
        debug!("querying {:?}", query_str);
        n_queries += 1;
        let mut results = query(ldap, &search_base, &query_str).await?;
        results.sort_by(|a, b| cmp_attr(a, b, "cn"));
        for result in results {
            handle_result(
                &result,
                &mut cur_state,
                &mut remaining,
                &root_user,
                &mut hier_fh,
            )
            .await?
        }
    }
    info!("Completed with {} individual queries", n_queries);

    let should_write_cur_state = if let Ok(old_ss_fh) = std::fs::File::open(&state_filepath) {
        let old_ss: SavedState = serde_json::from_reader(old_ss_fh)?;
        let changes = find_changes(&old_ss, &cur_state);
        if changes.is_empty() {
            false
        } else {
            // Write 'em out
            let mut changes_path = state_dir.clone();
            let now = chrono::Utc::now();
            changes_path.push(format!("{}-diffs-{}.txt", root_user, now.format("%Y-%m-%d-%H-%M-%S")));
            let mut changes_fh = tokio::fs::File::create(&changes_path).await?;
            for change in changes {
                changes_fh.write_all(change.as_bytes()).await?;
                changes_fh.write_all(b"\n").await?;
            }
            println!("CHANGES_{}={:?}", root_user, changes_path);
            true
        }
    } else {
        // Didn't have a saved state
        true
    };

    if should_write_cur_state {
        std::fs::write(state_filepath, serde_json::to_string(&cur_state)?)?;
        std::fs::rename(dump_filepath_tmp, dump_filepath)?;
    } else {
        std::fs::remove_file(dump_filepath_tmp)?;
    }
    Ok(())
}

async fn handle_result(
    result: &SearchEntry,
    cur_state: &mut SavedState,
    remaining: &mut VecDeque<String>,
    root_user: &str,
    heir_fh: &mut tokio::fs::File,
) -> Result<()> {
    let this_username =
        get_attr(&result, "cn").ok_or_else(|| anyhow!("Record for {} missing CN", result.dn))?;

    if let Some(Some(manager_userid)) = result
        .attrs
        .get("manager")
        .map(|m| m.get(0).unwrap())
        .map(|m| dn2user(m))
    {
        cur_state
            .emp_manager
            .insert(this_username.to_owned(), manager_userid.to_owned());

        if let Some(attr_reports) = result.attrs.get("directReports") {
            if !attr_reports.is_empty() {
                let mut these_reports = attr_reports
                    .iter()
                    .map(|dn| dn2user(dn).unwrap().to_owned())
                    .collect::<Vec<String>>();
                these_reports.sort();
                cur_state
                    .manager_reports
                    .insert(this_username.to_owned(), these_reports.clone());
                // remaining.append(&mut these_reports);
                these_reports
                    .into_iter()
                    .for_each(|userid| remaining.push_back(userid));
            }
        }
    }

    heir_fh
        .write_all(generate_oneliner(root_user, this_username, &cur_state.emp_manager).as_bytes())
        .await?;
    Ok(())
}

// fn build_query(users: &[String]) -> String {
fn build_query(users: &mut VecDeque<String>) -> String {
    let max = if users.len() > MAX_QUERY_USERS {
        MAX_QUERY_USERS
    } else {
        users.len()
    };
    format!(
        "(|{})",
        users
            .drain(0..max)
            .map(|u| format!("(CN={})", ldap3::ldap_escape(u)))
            .collect::<Vec<String>>()
            .join("")
    )
}

async fn query(ldap: &mut Ldap, search_base: &str, query: &str) -> Result<Vec<SearchEntry>> {
    let (rs, _res) = ldap
        .search(
            search_base,
            Scope::Subtree,
            query,
            // vec!["CN", "directReports", "manager"],
            vec!["*"],
        )
        .await?
        .success()?;
    Ok(rs
        .into_iter()
        .map(SearchEntry::construct)
        .collect::<Vec<SearchEntry>>())
}

fn dn2user(dn: &str) -> Option<&str> {
    dn.split(',')
        .find(|s| s.starts_with("CN="))
        .map(|s| &s[3..])
}

/**
 * Print out a one-line record for this user's hierarchy
 */
fn generate_oneliner(
    root_user: &str,
    user: &str,
    emp_manager: &BTreeMap<String, String>,
) -> String {
    let mut oneliner = String::new();
    let mut this_username = user;
    let mut hier = vec![this_username];
    while this_username != root_user {
        match emp_manager.get(this_username) {
            Some(manager_userid) => {
                hier.push(manager_userid);
                this_username = manager_userid;
            }
            None => {
                warn!("No manager for {}?", this_username);
                break;
            }
        }
    }

    hier.into_iter().rev().enumerate().for_each(|(i, u)| {
        oneliner.push_str(format!("{}{}", if i > 0 { "," } else { "" }, u).as_str())
    });
    oneliner.push('\n');
    oneliner
}

fn find_changes(old_state: &SavedState, cur_state: &SavedState) -> Vec<String> {
    let mut changes = compare_managers(&old_state, &cur_state);
    let mut direct_report_changes = compare_reports(&old_state, &cur_state);
    if !direct_report_changes.is_empty() {
        changes.push("".to_owned());
        changes.append(&mut direct_report_changes);
    }

    changes
}

fn compare_managers(old_ss: &SavedState, cur_ss: &SavedState) -> Vec<String> {
    let mut changes = vec![];
    let mut new_users: HashSet<&str> = HashSet::new();
    cur_ss.emp_manager.keys().for_each(|u| {
        new_users.insert(u);
    });
    for (userid, old_manager) in &old_ss.emp_manager {
        new_users.remove(userid.as_str());
        if let Some(cur_manager) = cur_ss.emp_manager.get(userid) {
            if cur_manager != old_manager {
                changes.push(format!(
                    "  {} now reports to {} (was {})",
                    userid, cur_manager, old_manager
                ))
            }
        } else {
            changes.push(format!("  {} no longer exists", userid));
        }
    }
    new_users.into_iter().for_each(|userid| {
        changes.push(format!(
            "  {} is new, reports to {}",
            userid,
            cur_ss.emp_manager.get(userid).unwrap()
        ))
    });
    if !changes.is_empty() {
        changes.insert(0, "Employee manager changes\n".to_owned());
    }
    changes
}

fn compare_reports(old_ss: &SavedState, cur_ss: &SavedState) -> Vec<String> {
    let mut changes = vec![];
    let mut new_managers = HashSet::new();
    // Assume everyone is new until we see they were already there
    cur_ss.manager_reports.keys().for_each(|m| {
        new_managers.insert(m);
    });

    for (manager, old_reports) in &old_ss.manager_reports {
        let mut new_reports = vec![];

        // Not new
        new_managers.remove(manager);
        if let Some(cur_reports) = cur_ss.manager_reports.get(manager) {
            // Something changed?  Go find it
            if old_reports != cur_reports {
                let mut old_reports: HashSet<String> = old_reports.clone().into_iter().collect();
                cur_reports.into_iter().for_each(|cur_report| {
                    if !old_reports.contains(cur_report) {
                        new_reports.push(cur_report);
                    } else {
                        old_reports.remove(cur_report);
                    }
                });
                // Found some new employees
                if !new_reports.is_empty() {
                    changes.push(format!(
                        "  {} now report(s) to {}",
                        new_reports.iter().format(", "),
                        manager
                    ));
                }
                // Anyone we didn't see?
                if !old_reports.is_empty() {
                    let mut del_reports = old_reports.drain().collect::<Vec<String>>();
                    del_reports.sort();
                    changes.push(format!(
                        "  {} no longer report(s) to {}",
                        del_reports.iter().format(", "),
                        manager
                    ));
                }
            }
        } else {
            changes.push(format!("  {} no longer has any reports", manager))
        }
    }

    // Anyone with reports that didn't exist before?
    new_managers.into_iter().for_each(|manager| {
        changes.push(format!(
            "  {} now report to NEW manager {}",
            cur_ss
                .manager_reports
                .get(manager)
                .unwrap()
                .iter()
                .format(", "),
            manager
        ))
    });

    if !changes.is_empty() {
        changes.insert(0, "Manager employee changes\n".to_owned());
    }
    changes
}
