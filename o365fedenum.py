import requests, json, argparse, random, numpy
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)



class RequestAnalyzer(object):

    def __init__(self, debugfile):
        self.debugfile = debugfile
        self.baseline_invalid = {}
        self.baseline_valid = {}
        self.error_response = {}
        self.request_count_invalid = 0
        self.request_count_valid = 0

        self.identical_resp = None
        self.keys_valid = None
        self.keys_invalid = None

        self.baseline = {}
        self.current_response = {}


    def add_request_known_invalid(self,r):
        self.request_count_invalid += 1

        if self.baseline_invalid == {}:
            self.baseline_invalid['StatusCode'] = [[r.status_code, 1]]
            for header in r.headers:
                if header == "X-AutoDiscovery-Error":
                    continue
                self.baseline_invalid["HEADER-"+header] = [[r.headers[header], 1]]
            self.baseline_invalid['Body'] = [[r.text, 1]]
            self.deconstruct_error(r.headers['X-AutoDiscovery-Error'])

        else:
            self.deconstruct_error(r.headers['X-AutoDiscovery-Error'])
            for key in self.baseline_invalid:
                req_data = None
                if key == "StatusCode":
                    req_data = r.status_code
                elif key == "Body":
                    req_data = r.text
                elif key == "HEADER-X-AutoDiscovery-Error":
                    continue
                else:
                    try:
                        req_data = r.headers["HEADER-".join(key.split("HEADER-")[1:])]
                    except:
                        continue

                found = False
                for value in self.baseline_invalid[key]:
                    if value[0] == req_data:
                        found = True
                        value[1] += 1

                if found == False:
                    self.baseline_invalid[key].append([req_data, 1])


    def add_request_known_valid(self,r):
        self.request_count_valid += 1

        if self.baseline_valid == {}:
            self.baseline_valid['StatusCode'] = [[r.status_code, 1]]
            for header in r.headers:
                if header == "X-AutoDiscovery-Error":
                    continue
                self.baseline_valid["HEADER-"+header] = [[r.headers[header], 1]]
            self.baseline_valid['Body'] = [[r.text, 1]]
            self.deconstruct_error(r.headers['X-AutoDiscovery-Error'], invalid=False)

        else:
            self.deconstruct_error(r.headers['X-AutoDiscovery-Error'], invalid=False)
            for key in self.baseline_valid:
                req_data = None
                if key == "StatusCode":
                    req_data = r.status_code
                elif key == "Body":
                    req_data = r.text
                elif key == "HEADER-X-AutoDiscovery-Error":
                    continue
                else:
                    try:
                        req_data = r.headers["HEADER-".join(key.split("HEADER-")[1:])]
                    except:
                        continue

                found = False
                for value in self.baseline_valid[key]:
                    if value[0] == req_data:
                        found = True
                        value[1] += 1

                if found == False:
                    self.baseline_valid[key].append([req_data, 1])


    def deconstruct_error(self,error,invalid=True,current=False):
        header_name = "HEADER-X-AutoDiscovery-Error-"
        for item in error.split("<"):
            for item1 in item.split(">"):
                for item2 in item1.split(","): # POSSIBLE BUG HERE
                    if item2 != "":
                        key = header_name + item2
                        if invalid:
                            if key not in self.baseline_invalid:
                                self.baseline_invalid[key] = [[item2, 1]]
                            else:
                                self.baseline_invalid[key][0][1] += 1
                        elif current:
                            if key not in self.current_response:
                                self.current_response[key] = [[item2, 1]]
                            else:
                                self.current_response[key][0][1] += 1
                        else:
                            if key not in self.baseline_valid:
                                self.baseline_valid[key] = [[item2, 1]]
                            else:
                                self.baseline_valid[key][0][1] += 1


    def correlate(self):

        log_data(self.debugfile, "Generating valid/invalid response baselines")

        self.keys_invalid = list(self.baseline_invalid.keys())
        self.keys_valid = list(self.baseline_valid.keys())

        inconsistent_keys = []
        for key in self.keys_invalid:
            if len(self.baseline_invalid[key]) > 1:
                del self.baseline_invalid[key]
                del self.baseline_valid[key]
                inconsistent_keys.append(key)
            elif self.baseline_invalid[key][0][1] < self.request_count_invalid:
                try:
                    del self.baseline_invalid[key]
                    del self.baseline_valid[key]
                    inconsistent_keys.append(key)
                except:
                    continue

        # print(inconsistent_keys)

        self.keys_invalid = list(self.baseline_invalid.keys())
        self.keys_valid = list(self.baseline_valid.keys())

        self.identical_resp = list(numpy.intersect1d(self.keys_invalid, self.keys_valid))

        for key in self.identical_resp:
        #     self.keys_invalid.remove(entry)
        #     self.keys_valid.remove(entry)
            if self.baseline_valid[key][0][0] == self.baseline_invalid[key][0][0]:
                del self.baseline_invalid[key]
                del self.baseline_valid[key]

        self.keys_invalid = list(self.baseline_invalid.keys())
        self.keys_valid = list(self.baseline_valid.keys())

        self.baseline = {
            'valid' : self.keys_valid,
            'invalid' : self.keys_invalid
        }

        log_data(self.debugfile, "Found {} indicators of invalid user".format(len(self.keys_invalid)))
        log_data(self.debugfile, "Found {} indicators of valid user".format(len(self.keys_valid)))


    def test_user_response(self,username,r):

        self.current_response = {}

        self.current_response['StatusCode'] = [[r.status_code, 1]]
        for header in r.headers:
            if header == "X-AutoDiscovery-Error":
                continue
            self.current_response["HEADER-"+header] = [[r.headers[header], 1]]
        self.current_response['Body'] = [[r.text, 1]]
        log_data(self.debugfile, r.headers, False)
        self.deconstruct_error(r.headers['X-AutoDiscovery-Error'], invalid=False, current=True)

        # print(self.current_response)

        valid_count = 0
        for key in self.baseline['valid']:
            if key in self.current_response and self.current_response[key][0][0] == self.baseline_valid[key][0][0]:
                # print(key)
                valid_count += 1

        invalid_count = 0
        for key in self.baseline['invalid']:
            if key in self.current_response and self.current_response[key][0][0] == self.baseline_invalid[key][0][0]:
                # print(key)
                invalid_count += 1

        if valid_count > invalid_count:
            return "[+] Valid User {uname}, Valid Match count: {count}".format(uname=username, count=valid_count)
        elif valid_count == invalid_count:
            return "[+] Possible Valid User {uname}, equal match count: {count}".format(uname=username, count=valid_count)
        else:
            return "[-] Invalid User {uname}, Invalid Match count: {count}".format(uname=username, count=invalid_count)


    def print_baseline(self):

        log_data(self.debugfile, "\n[*] Factors indicating invalid hits:")
        for key in self.baseline['invalid']:
            if "X-AutoDiscovery-Error" in key:
                printstr = "HEADER-X-AutoDiscovery-Error"
            else:
                printstr = key
            log_data(self.debugfile, "\t{} : {}".format(printstr, self.baseline_invalid[key][0][0]))


        log_data(self.debugfile, "\n[*] Factors indicating valid hits:")
        for key in self.baseline['valid']:
            if "X-AutoDiscovery-Error" in key:
                printstr = "HEADER-X-AutoDiscovery-Error"
            else:
                printstr = key
            log_data(self.debugfile, "\t{} : {}".format(printstr, self.baseline_valid[key][0][0]))


def log_data(debugfile, data, do_print=True):

    if debugfile is not None:
        f = open(debugfile, 'a')
        f.write(str(data))
        f.write('\n')
        f.close()

    if do_print:
        print(data)


def main(args):

    testfile = args.testfile
    domain = args.domain
    valid = args.valid
    debugfile = args.debug

    password = "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(32)) # args.password

    headers = {"Content-Type": "text/xml"}


    users = []
    for i in range(0,5):
        uname = "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(20))
        users.append(uname + "@{}".format(domain.strip()))

    analyzer = RequestAnalyzer(debugfile)


    for user in users:

        log_data(debugfile, "Requesting: {}".format(user))

        r = requests.get("https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml", auth=(user.strip(), password), verify=False)
        # print('\n\n')
        # print(r.headers)
        # print(r.cookies)
        # print(r.text)
        # print(r.status_code)

        analyzer.add_request_known_invalid(r)

    if domain.strip() not in valid.strip():
        valid = valid + "@{}".format(domain.strip())

    log_data(debugfile, "Requesting Valid: {}".format(valid.strip()))
    user = valid.strip()
    r = requests.get("https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml", auth=(user.strip(), password), verify=False)
    analyzer.add_request_known_valid(r)
    log_data(debugfile, "Finished")

    analyzer.correlate()
    if args.verbose:
        analyzer.print_baseline()

    log_data(debugfile, "\n\nTesting users")

    users = open(testfile,'r').readlines()
    for user in users:
        # print("Requesting: {}".format(user.strip()))
        if domain.strip() not in user:
            user = user + "@{}".format(domain.strip())
        r = requests.get("https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml", auth=(user.strip(), password), verify=False)

        log_data(debugfile, analyzer.test_user_response(user.strip(),r))


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--testfile', default=None, required=True, help='Username to test file')
    parser.add_argument('-d', '--domain', default=None, required=True, help='Office365 Tenant Domain')
    parser.add_argument('-v', '--valid', default=None, required=True, help='Known valid email address, like a point of contact email')
    parser.add_argument('--verbose', default=False, action="store_true", help='Display raw baseline data')
    parser.add_argument('--debug', default=None, required=False, help='Output full response & data to debug file')
    #
    args = parser.parse_args()
    # args = None
    main(args)
