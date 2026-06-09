import subprocess

TARGET = "https://www.concertcircle.com/"


def run_hakrawler(target):
    cmd = f'echo "{target}" | hakrawler -subs'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.splitlines()


def clean_urls(urls):
    cleaned = set()

    for url in urls:

        # Keep only localhost scope
        if "localhost" not in url:
            continue

        # Remove static files
        

        # Remove directory listing junk
      

        cleaned.add(url.strip())

    return sorted(cleaned)


def save_to_file(urls, filename="endpoints.txt"):
    with open(filename, "w") as f:
        for url in urls:
            f.write(url + "\n")


if __name__ == "__main__":

    print("\n[+] Running hakrawler...\n")

    raw_urls = run_hakrawler(TARGET)

    print("[+] Cleaning results...\n")

    clean_list = clean_urls(raw_urls)

    for url in clean_list:
        print(url)

    save_to_file(clean_list)

    print(f"\n✅ Saved {len(clean_list)} endpoints to endpoints.txt\n")
