from ingestion.log_reader import follow

def main():
    print("[*] InsightLog started")

    try:
        for line in follow():
            print(line)  # Later → parse, detect, store

    except PermissionError:
        print("[!] Run with sudo.")
    except KeyboardInterrupt:
        print("\n[*] Stopped safely.")

if __name__ == "__main__":
    main()