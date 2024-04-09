import subprocess
import argparse
import json
import re
import requests


IP_REGEX = re.compile(r"(?P<IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
TIMEOUT_REGEX = re.compile(r"\*.*?\*.*?\*")
API_ENDPOINT = "http://ip-api.com/batch"


def trace(domain: str, hops: int, wait: int):
    ips = []
    with subprocess.Popen(["tracert", "-h", str(hops), "-w", str(wait), domain],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as tracer:
        for line in tracer.stdout:
            line = line.decode("cp866")
            match_ip = IP_REGEX.search(line)
            match_timeout = TIMEOUT_REGEX.search(line)
            if match_ip:
                ips.append(match_ip.group("IP"))
            if match_timeout:
                tracer.terminate()
        if len(ips) <= 1:
            print("Invalid domain/IP")
            return
        dest = ips.pop(0)
        if ips[-1] != dest:
            ips.append(dest)
        tracer.wait()
    response = find_ips(ips)
    for item in response:
        if all(key in item for key in ("org", "city", "country")):
            output = f'"{item["org"]}" {item["city"]}, {item["country"]}:'
            print(output, end=" ")
        print(item["query"])


def find_ips(ips: list):
    data = json.dumps(ips)
    response = requests.post(API_ENDPOINT, data=data, timeout=100)
    return response.json()


def main():
    parser = argparse.ArgumentParser(
        prog="tracer",
        description="A tool that traces IP packet as it traverses routers locally or globally")
    parser.add_argument("--hops", action="store", type=int,
                        default=30, help="max amount of hops")
    parser.add_argument("--wait", action="store", type=int,
                        default=100, help="max wait timeout for each answer in ms")
    parser.add_argument("domain", action="store",
                        help="domain/IP to trace the route to")
    args = parser.parse_args()

    if args.hops <= 0 or args.wait <= 0:
        print("Invalid arguments")
    else:
        trace(args.domain, args.hops, args.wait)


if __name__ == "__main__":
    main()
