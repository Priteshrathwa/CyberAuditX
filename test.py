import subprocess

domain = input("Enter target domain: ").strip()

subs_file = "subs.txt"
live_file = "live_subs.txt"


def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


print("\n[+] Enumerating subdomains...\n")
subs = run_command(f"subfinder -d {domain} -silent")
with open(subs_file, "w") as f:
    f.write(subs)

print(subs)


print("[+] Checking alive subdomains...\n")
live_subs = run_command(f"httpx -l {subs_file} -silent")
with open(live_file, "w") as f:
    f.write(live_subs)

print(live_subs)


print("✅ Subdomain automation completed\n")
print(f"Saved to:\n- {subs_file}\n- {live_file}")
