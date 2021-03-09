use clap::{App, Arg, SubCommand};
use std::{fs, io::{self, Write}, path::Path};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::io::prelude::*;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const MOUNT_POINT: &str = "/tmp/sandcastle";

const MAXIMUM_QUOTA_MC: u32 = 1000;
const MAXIMUM_SHARE_MC: u32 = 1000;
const MAXIMUM_QUOTA_MS: u32 = 100000;
const MAXIMUM_SHARE_MS: u32 = 1024;

fn main() {
    let matches = App::new("Sandcastle")
        .version("0.1")
        .author("Vigneshwar S <vigneshwar.sm@zohocorp.com>")
        .subcommand(SubCommand::with_name("run")
            .about("Runs target process in a container")
            .arg(Arg::with_name("target")
                .short("t")
                .long("target")
                .help("Sets absolute path of target program")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("quota")
                .short("q")
                .long("quota")
                .help("Sets CPU quota for target program in millcores")
                .min_values(1)
                .max_values(MAXIMUM_QUOTA_MC as u64)
                .takes_value(true))
            .arg(Arg::with_name("share")
                .short("s")
                .long("share")
                .help("Sets CPU share for target program in millicores")
                .min_values(1)
                .max_values(MAXIMUM_SHARE_MC as u64)
                .takes_value(true))
            .arg(Arg::with_name("limit")
                .short("l")
                .long("limit")
                .help("Sets fork limit for target process")
                .takes_value(true))
            .arg(Arg::with_name("cpuset")
                .short("c")
                .long("cpuset")
                .help("Sets CPU nodes for target process")
                .takes_value(true))
            .arg(Arg::with_name("memset")
                .short("m")
                .long("memset")
                .help("Sets memory nodes for target process")
                .takes_value(true))
            .arg(Arg::with_name("mountns")
                .short("M")
                .long("mountns")
                .help("Creates new mount namespace for target"))
            .arg(Arg::with_name("utsns")
                .short("u")
                .long("utsns")
                .help("Creates new UTS namespace for target"))
            .arg(Arg::with_name("userns")
                .short("U")
                .long("userns")
                .help("Creates new user namespace for target")))
        .subcommand(SubCommand::with_name("stats")
            .about("Shows resource usage statistics for a container")
            .arg(Arg::with_name("sandcastle_id")
                .short("i")
                .long("sandcastle_id")
                .help("Generated sandcastle container ID")
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("list")
            .about("Lists all running containers"))
        .subcommand(SubCommand::with_name("clear")
            .about("Clears all containers. (For debugging purposes)"))
        .get_matches();

    match create_root_dirs() {
        Ok(_) => {},
        Err(msg) => panic!("create_root_dirs() failed! : {}", msg)
    }

    if let Some(matches) = matches.subcommand_matches("run") {
        let id = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(seconds) => {
                let mut hasher = DefaultHasher::new();
                hasher.write(seconds.as_secs_f64().to_string().as_bytes());
                hasher.finish()
            },
            Err(_) => panic!("Some internal error occured!")
        };

        let target = matches.value_of("target").unwrap();

        let quota: u32 = matches.value_of("quota")
            .unwrap_or(&MAXIMUM_QUOTA_MC.to_string()).trim().parse().unwrap();
        let quota = quota / MAXIMUM_QUOTA_MC * MAXIMUM_QUOTA_MS;

        let share: u32 = matches.value_of("share")
            .unwrap_or(&MAXIMUM_SHARE_MC.to_string()).trim().parse().unwrap();
        let share = share / MAXIMUM_SHARE_MC * MAXIMUM_SHARE_MS;

        let limit = matches.value_of("limit").unwrap_or("max");

        let cpuset = matches.value_of("cpuset").unwrap_or("0-3");
        let memset = matches.value_of("memset").unwrap_or("0");

        println!("Container spinned up with id: {}", id);
        
        let command = Command::new("/home/local/ZOHOCORP/vignesh-pt3767/jailer/target/debug/jailer")
            .arg("-i").arg(id.to_string())
            .arg("-t").arg(target.to_string())
            .arg("-q").arg(quota.to_string())
            .arg("-s").arg(share.to_string())
            .arg("-l").arg(limit)
            .arg("-c").arg(cpuset)
            .arg("-m").arg(memset)
            .arg("-M")
            .arg("-u")
            .arg("-U");
        if matches.is_present("mountns") { command = command.arg("-M") }
        if matches.is_present("utsns") { command = command.arg("-u") }
        if matches.is_present("userns") { command = command.arg("-U") }
        
        let output = command.output().unwrap();
        println!("Jailer exit code: {}", output.status);
        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
    }

    if let Some(_) = matches.subcommand_matches("list") {
        list_containers();
    }

    if let Some(_) = matches.subcommand_matches("clear") {
        clear_containers();
    }

    if let Some(matches) = matches.subcommand_matches("stats") {
        let process_id = matches.value_of("sandcastle_id").unwrap();
        
        if !Path::new(&format!("{}/cpuacct/sandcastle/{}/", CGROUP_ROOT, process_id)[..]).is_dir() {
            println!("No process found with ID: {}", process_id);
        } else {
            println!("Stats for sandcastle ID: {}", process_id);
            print_stats(process_id);
        }
    }
}

fn create_root_dirs() -> Result<(), io::Error> {
    if !Path::new(MOUNT_POINT).is_dir() || !Path::new(&format!("{}/cpuacct/sandcastle", CGROUP_ROOT)[..]).is_dir() {
        fs::create_dir_all(MOUNT_POINT)?;

        fs::create_dir_all(&format!("{}/cpuacct/sandcastle/", CGROUP_ROOT)[..])?;
        fs::create_dir_all(&format!("{}/cpu/sandcastle/", CGROUP_ROOT)[..])?;
        fs::create_dir_all(&format!("{}/cpuset/sandcastle/", CGROUP_ROOT)[..])?;
        fs::create_dir_all(&format!("{}/pids/sandcastle/", CGROUP_ROOT)[..])?;

        let path = format!("{}/cpuset/sandcastle/", CGROUP_ROOT);

        let mut mems_file = fs::OpenOptions::new().append(true).open(format!("{}/cpuset.mems", path))?;
        mems_file.write("0".as_bytes())?;

        let mut cpus_file = fs::OpenOptions::new().append(true).open(format!("{}/cpuset.cpus", path))?;
        cpus_file.write("0-3".as_bytes())?;
    }

    Ok(())
}

fn list_containers() {
    if let Ok(sandcastle) = fs::read_dir(MOUNT_POINT) {
        println!("Container ID\tUser Program");

        for container in sandcastle {
            if let Ok(container) = container {
                if container.file_type().unwrap().is_dir() {
                    let mut target = String::new();
                    let mut config = match fs::OpenOptions::new().read(true)
                        .open(format!("{}/config", container.path().into_os_string().into_string().unwrap())) {
                        Ok(file) => file,
                        Err(_) => {
                            println!("Failed to read config for {}", container.file_name().into_string().unwrap());
                            continue;
                        }
                    };

                    config.read_to_string(&mut target).unwrap();
                    println!("{}\t{}", container.file_name().into_string().unwrap(), target);
                }
            }
        }
    }
}

fn clear_containers() {
    fs::remove_dir_all(MOUNT_POINT).unwrap();

    clean_cgroup(&format!("{}/cpu/sandcastle/", CGROUP_ROOT)[..]);
    clean_cgroup(&format!("{}/cpuset/sandcastle/", CGROUP_ROOT)[..]);
    clean_cgroup(&format!("{}/pids/sandcastle/", CGROUP_ROOT)[..]);
    clean_cgroup(&format!("{}/cpuacct/sandcastle/", CGROUP_ROOT)[..]);
}

fn clean_cgroup(path: &str) {
    if let Ok(sandcastle) = fs::read_dir(path) {
        for container in sandcastle {
            if let Ok(container) = container {
                if container.file_type().unwrap().is_dir() {
                    let mut current = String::from(path);
                    current.push_str(&container.file_name().into_string().unwrap()[..]);
                    fs::remove_dir(&current[..]).unwrap();
                }
            }
        }
    }
}

fn print_stats(process_id: &str) -> Result<(), io::Error> {
    let mut cpuacct = String::new();
    read_special(
        format!("{}/cpuacct/sandcastle/{}/cpuacct.usage_all", CGROUP_ROOT, process_id),
        &mut cpuacct
    )?;
    println!("CPU usage per core (both user and system):\n{}", cpuacct);

    let mut cpu_usage = String::new();
    read_special(
        format!("{}/cpuacct/sandcastle/{}/cpuacct.usage", CGROUP_ROOT, process_id),
        &mut cpu_usage
    )?;
    println!("Total CPU usage by user and system:\n{}", cpu_usage);

    let mut cpuacct_stat = String::new();
    read_special(
        format!("{}/cpuacct/sandcastle/{}/cpuacct.usage", CGROUP_ROOT, process_id),
        &mut cpuacct_stat
    )?;
    println!("CPU usage by user and system:\n{}", cpuacct_stat);

    let mut cpu_stat = String::new();
    read_special(
        format!("{}/cpuacct/sandcastle/{}/cpu.stat", CGROUP_ROOT, process_id),
        &mut cpu_stat
    )?;
    println!("Other CPU stats:\n{}", cpu_stat);

    Ok(())
}

fn read_special(file: &String, buffer: &mut String) -> Result<(), io::Error> {
    let mut file = fs::OpenOptions::new().read(true).open(&file[..])?;
    file.read_to_string(buffer)?;

    Ok(())
}