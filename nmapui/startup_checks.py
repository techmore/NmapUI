import subprocess


def run_startup_checks(deps, quick=False):
    begin_startup_state = deps["begin_startup_state"]
    check_arp_scan = deps["check_arp_scan"]
    check_nmap = deps["check_nmap"]
    check_vulners = deps["check_vulners"]
    complete_startup_state = deps["complete_startup_state"]
    get_app_version = deps["get_app_version"]
    get_default_interface_cached = deps["get_default_interface_cached"]
    get_versions = deps["get_versions"]
    load_auto_scan_config = deps["load_auto_scan_config"]
    load_current_assignment = deps["load_current_assignment"]
    logger = deps["logger"]
    network_key = deps["network_key"]
    run_traceroute = deps["run_traceroute"]
    safe_emit = deps["safe_emit"]
    startup_state = deps["startup_state"]
    tool_versions = deps["tool_versions"]
    auto_scan_config = deps["auto_scan_config"]
    vulners_script = deps["vulners_script"]

    import platform

    begin_startup_state(startup_state, quick=quick)
    load_auto_scan_config(auto_scan_config)

    logger.info("\n" + "=" * 50)
    logger.info("NmapUI Startup Checks")
    logger.info("=" * 50)

    system_platform = platform.system()
    platform_release = platform.release()
    logger.info(f"Platform detected: {system_platform} ({platform_release})")
    default_interface = get_default_interface_cached()
    logger.info(f"Default Network Interface: {default_interface}")

    if quick:
        logger.info("Quick mode: skipping dependency checks")
        startup_state["dependencies_ok"] = True
    else:
        logger.info("\nChecking nmap...")
        tool_versions.set_version("nmap", check_nmap())

        logger.info("\nChecking vulners script...")
        check_vulners(vulners_script)
        vulners_dir = vulners_script.parent
        if vulners_dir.exists():
            try:
                version_result = subprocess.run(
                    [
                        "git",
                        "log",
                        "-1",
                        "--oneline",
                        "--date=short",
                        "--pretty=format:%h %ad %s",
                    ],
                    cwd=vulners_dir,
                    capture_output=True,
                    text=True,
                )
                if version_result.returncode == 0:
                    tool_versions.set_version("vulners", version_result.stdout.strip())
                else:
                    tool_versions.set_version("vulners", "Unknown")
            except Exception:
                tool_versions.set_version("vulners", "Unknown")

        logger.info("\nChecking arp-scan...")
        if check_arp_scan():
            try:
                version = (
                    subprocess.check_output(
                        ["arp-scan", "--version"], stderr=subprocess.STDOUT
                    )
                    .decode()
                    .split("\n")[0]
                )
                tool_versions.set_version("arp_scan", version)
            except Exception:
                tool_versions.set_version("arp_scan", "arp-scan (version unknown)")
        else:
            tool_versions.set_version("arp_scan", "Not installed")
        startup_state["dependencies_ok"] = True

    logger.info("\nLoading previous customer assignment...")
    load_current_assignment()

    logger.info("\nInitializing network key...")
    run_traceroute("1.1.1.1")
    complete_startup_state(
        startup_state,
        traceroute_initialized=not bool(network_key.get("error")),
    )
    logger.info(f"Network key initialized with {network_key.get('total_hops', 0)} hops")

    logger.info("\n" + "=" * 50)
    logger.info("All checks passed. Starting server...")
    logger.info("=" * 50 + "\n")

    tool_versions.set_version("app", get_app_version())
    safe_emit("versions", get_versions())
    safe_emit("auto_scan_status", auto_scan_config)
