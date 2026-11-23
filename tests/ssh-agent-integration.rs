use std::{ffi::OsString, io};

use harness::{SshAgentInstance, SshPkiKeygen};

mod harness;
mod keys;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn make_openssh_agent_with_keys() -> io::Result<SshAgentInstance> {
    let agent = SshAgentInstance::new_openssh()?;
    println!("{:#?}", agent);

    for key in keys::PRIVATE {
        agent.add(key)?;
    }

    Ok(agent)
}

fn make_openssh_agent_with_certs() -> io::Result<SshAgentInstance> {
    let agent = SshAgentInstance::new_openssh()?;
    println!("{:#?}", agent);

    let mut pki = SshPkiKeygen::new()?;
    for key in keys::PRIVATE {
        let cert = pki.sign(key)?;
        agent.add_cert(key, cert)?;
    }

    Ok(agent)
}

fn assert_all_keys_in_agent(agent: &SshAgentInstance) -> TestResult {
    let keys_in_agent = agent.list()?;
    for key in keys::PUBLIC {
        assert!(keys_in_agent.iter().any(|v| v == key));
    }

    Ok(())
}

#[test]
fn add_keys_to_openssh_agent() -> TestResult {
    let agent = make_openssh_agent_with_keys()?;

    assert_all_keys_in_agent(&agent)?;

    Ok(())
}

#[test]
fn add_certs_to_openssh_agent() -> TestResult {
    let agent = make_openssh_agent_with_certs()?;

    assert_all_keys_in_agent(&agent)?;

    Ok(())
}

#[test]
fn empty_mux_agent() -> TestResult {
    let agent = SshAgentInstance::new_mux("", None::<OsString>)?;

    let keys_in_agent = agent.list()?;
    assert!(keys_in_agent.is_empty());

    Ok(())
}

#[test]
fn mux_with_one_agent() -> TestResult {
    let openssh_agent = make_openssh_agent_with_keys()?;
    let mux_agent = SshAgentInstance::new_mux(
        &format!(
            r##"agent_sock_paths = ["{}"]"##,
            openssh_agent.sock_path.display()
        ),
        None::<OsString>,
    )?;

    assert_all_keys_in_agent(&mux_agent)?;

    Ok(())
}

#[test]
fn mux_with_three_agents() -> TestResult {
    let agent_rsa = SshAgentInstance::new_openssh()?;
    agent_rsa.add(keys::TEST_KEY_RSA)?;
    let agent_ecdsa = SshAgentInstance::new_openssh()?;
    agent_ecdsa.add(keys::TEST_KEY_ECDSA)?;
    let agent_ed25519 = SshAgentInstance::new_openssh()?;
    agent_ed25519.add(keys::TEST_KEY_ED25519)?;

    let mux_agent = SshAgentInstance::new_mux(
        &format!(
            r##"agent_sock_paths = ["{}", "{}", "{}"]"##,
            dbg!(&agent_rsa).sock_path.display(),
            dbg!(&agent_ecdsa).sock_path.display(),
            dbg!(&agent_ed25519).sock_path.display()
        ),
        None::<OsString>,
    )?;

    assert_all_keys_in_agent(dbg!(&mux_agent))?;

    Ok(())
}

#[test]
fn mux_with_one_agent_with_certs() -> TestResult {
    let openssh_agent = make_openssh_agent_with_certs()?;
    let mux_agent = SshAgentInstance::new_mux(
        &format!(
            r##"agent_sock_paths = ["{}"]"##,
            openssh_agent.sock_path.display()
        ),
        None::<OsString>,
    )?;

    assert_all_keys_in_agent(&mux_agent)?;

    Ok(())
}

fn mux_over(agents: &[&SshAgentInstance]) -> io::Result<SshAgentInstance> {
    let paths: Vec<String> = agents
        .iter()
        .map(|a| format!("\"{}\"", a.sock_path.display()))
        .collect();
    SshAgentInstance::new_mux(
        &format!("agent_sock_paths = [{}]", paths.join(", ")),
        None::<OsString>,
    )
}

#[test]
fn sign_routes_to_owning_agent() -> TestResult {
    let agent_rsa = SshAgentInstance::new_openssh()?;
    agent_rsa.add(keys::TEST_KEY_RSA)?;
    let agent_ecdsa = SshAgentInstance::new_openssh()?;
    agent_ecdsa.add(keys::TEST_KEY_ECDSA)?;
    let agent_ed25519 = SshAgentInstance::new_openssh()?;
    agent_ed25519.add(keys::TEST_KEY_ED25519)?;
    let mux_agent = mux_over(&[&agent_rsa, &agent_ecdsa, &agent_ed25519])?;

    for pubkey in keys::PUBLIC {
        assert!(
            mux_agent.sign_and_verify(pubkey)?,
            "signing failed for {pubkey}"
        );
    }

    Ok(())
}

#[test]
fn sign_with_key_whose_upstream_holds_a_cert() -> TestResult {
    let openssh_agent = make_openssh_agent_with_certs()?;
    let mux_agent = mux_over(&[&openssh_agent])?;

    for pubkey in keys::PUBLIC {
        assert!(
            mux_agent.sign_and_verify(pubkey)?,
            "signing failed for {pubkey}"
        );
    }

    Ok(())
}

#[test]
fn sign_skips_missing_upstream() -> TestResult {
    let openssh_agent = make_openssh_agent_with_keys()?;
    let mux_agent = SshAgentInstance::new_mux(
        &format!(
            r##"agent_sock_paths = ["/nonexistent/agent.sock", "{}"]"##,
            openssh_agent.sock_path.display()
        ),
        None::<OsString>,
    )?;

    assert_all_keys_in_agent(&mux_agent)?;
    assert!(mux_agent.sign_and_verify(keys::TEST_KEY_ED25519_PUB)?);

    Ok(())
}

#[test]
fn add_key_through_mux() -> TestResult {
    let upstream = SshAgentInstance::new_openssh()?;
    let mux_agent = mux_over(&[&upstream])?;

    assert!(mux_agent.try_add(keys::TEST_KEY_ED25519)?);
    assert_eq!(
        upstream.list()?,
        vec![keys::TEST_KEY_ED25519_PUB.to_string()]
    );
    assert!(mux_agent.sign_and_verify(keys::TEST_KEY_ED25519_PUB)?);

    Ok(())
}

/// Regression test for upstream issue #90: `ssh-add -t` (and `step ssh login`) send
/// SSH_AGENTC_ADD_ID_CONSTRAINED (command 25), which must be forwarded.
#[test]
fn add_constrained_key_through_mux() -> TestResult {
    let upstream = SshAgentInstance::new_openssh()?;
    let mux_agent = mux_over(&[&upstream])?;

    assert!(mux_agent.try_add_with_lifetime(keys::TEST_KEY_ED25519, 3600)?);
    assert_eq!(
        upstream.list()?,
        vec![keys::TEST_KEY_ED25519_PUB.to_string()]
    );

    Ok(())
}

/// Keys are added only to the first upstream that accepts them; refusing upstreams (here a
/// locked agent, standing in for Secretive/1Password) are skipped, and later upstreams are
/// not touched.
#[test]
fn add_goes_to_first_accepting_upstream() -> TestResult {
    let refusing = SshAgentInstance::new_openssh()?;
    refusing.lock()?;
    let accepting = SshAgentInstance::new_openssh()?;
    let untouched = SshAgentInstance::new_openssh()?;
    let mux_agent = mux_over(&[&refusing, &accepting, &untouched])?;

    assert!(mux_agent.try_add(keys::TEST_KEY_ED25519)?);
    assert!(mux_agent.try_add_with_lifetime(keys::TEST_KEY_ECDSA, 3600)?);

    let mut accepted = accepting.list()?;
    accepted.sort();
    let mut expected = vec![
        keys::TEST_KEY_ED25519_PUB.to_string(),
        keys::TEST_KEY_ECDSA_PUB.to_string(),
    ];
    expected.sort();
    assert_eq!(accepted, expected);
    assert!(untouched.list()?.is_empty());

    Ok(())
}

#[test]
fn add_fails_when_no_upstream_accepts() -> TestResult {
    let refusing = SshAgentInstance::new_openssh()?;
    refusing.lock()?;
    let mux_agent = mux_over(&[&refusing])?;

    assert!(!mux_agent.try_add(keys::TEST_KEY_ED25519)?);
    assert!(!mux_agent.try_add_with_lifetime(keys::TEST_KEY_ED25519, 3600)?);

    Ok(())
}

#[test]
fn remove_routes_to_owning_agent() -> TestResult {
    let agent_rsa = SshAgentInstance::new_openssh()?;
    agent_rsa.add(keys::TEST_KEY_RSA)?;
    let agent_ed25519 = SshAgentInstance::new_openssh()?;
    agent_ed25519.add(keys::TEST_KEY_ED25519)?;
    let mux_agent = mux_over(&[&agent_rsa, &agent_ed25519])?;

    assert!(mux_agent.try_remove(keys::TEST_KEY_ED25519_PUB)?);
    assert!(agent_ed25519.list()?.is_empty());
    assert_eq!(agent_rsa.list()?, vec![keys::TEST_KEY_RSA_PUB.to_string()]);

    // Removing a key no upstream holds fails
    assert!(!mux_agent.try_remove(keys::TEST_KEY_ECDSA_PUB)?);

    Ok(())
}

#[test]
fn remove_all_clears_every_accepting_upstream() -> TestResult {
    let agent_rsa = SshAgentInstance::new_openssh()?;
    agent_rsa.add(keys::TEST_KEY_RSA)?;
    let agent_ed25519 = SshAgentInstance::new_openssh()?;
    agent_ed25519.add(keys::TEST_KEY_ED25519)?;
    let mux_agent = mux_over(&[&agent_rsa, &agent_ed25519])?;

    assert!(mux_agent.try_remove_all()?);
    assert!(mux_agent.list()?.is_empty());

    Ok(())
}
