#include <iostream>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>

// consider using this implementation
// https://github.com/noloader/SHA-Intrinsics

#include "DBXHash.h"

namespace po = boost::program_options;
void po_keyless(po::basic_parsed_options<char>& opts, std::vector<string>& keyless) {
    for (int j=0; j<opts.options.size(); j++) {
        po::basic_option<char> a = opts.options.at(j);
        if (a.string_key == "") {
            for (int i=0; i<a.value.size(); i++) {
                keyless.push_back(a.value[i]);
            }
        }
    }
}

int main(int argc, char** argv) {
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help", "produce help message")
            ("threads", po::value<string>(), "'all', 'half', or specify the number of threads to use");

    po::variables_map vm;
    po::basic_parsed_options<char> x = po::parse_command_line(argc, argv, desc);
    po::store(x, vm);
    po::notify(vm);

    std::vector<string> keyless;
    po_keyless(x, keyless);

    if (vm.count("help")) {
        cout << desc << endl;
        return 0;
    }

    // file list
    bool read_from_stdin = false;
    for (auto& v : keyless) {
        if (v == "-") {
            read_from_stdin = true;
            break;
        }
    }
    if (read_from_stdin and keyless.size() > 1) {
        cerr << "reading from stdin must be the only file argument if it is present" << endl;
        return 1;
    }
    if (keyless.empty()) read_from_stdin = true;

    // number of threads to use
    int all = (int) boost::thread::hardware_concurrency();
    int threads = all;
    if (vm.count("threads")) {
        string arg_threads = vm["threads"].as<string>();
        if (arg_threads == "all") threads = all;
        else if (arg_threads == "half") threads = all/2;
        else {
            int amount = boost::lexical_cast<int>(arg_threads);
            threads = std::min(std::max(amount, 1), all);
        }
    }


    byte hash[DIGEST_SIZE];

    if (read_from_stdin) {
        DBXHash(threads).process(std::cin, hash);
        cout << hexify(hash) << "  -" << endl;
    } else {
        for (string& path: keyless) {
            fs::ifstream file((fs::path(path)));
            if (! file.is_open()) {
                cerr << "failed to open file" << endl;
                return 2;
            }
            DBXHash(threads).process(file, hash);
            cout << hexify(hash) << "  " << path << endl;
            file.close();
        }
    }

    return 0;
}
