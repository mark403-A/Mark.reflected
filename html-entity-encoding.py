#!/usr/bin/env python3
import argparse
import html

def convert_payloads(input_file, output_file):
    try:
        with open(input_file, "r") as f:
            payloads = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Failed to read payload file: {e}")
        return

    try:
        with open(output_file, "w") as f_out:
            for p in payloads:
                encoded = html.escape(p)
                f_out.write(encoded + "\n")
        print(f"Converted {len(payloads)} payloads and saved to {output_file}")
    except Exception as e:
        print(f"Failed to write to output file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Convert XSS payloads to HTML entity encoded versions and save them.")
    parser.add_argument("-p", "--payloads", required=True, help="Input file with raw XSS payloads, one per line.")
    parser.add_argument("-o", "--output", required=True, help="Output file to save encoded payloads.")

    args = parser.parse_args()

    convert_payloads(args.payloads, args.output)

if __name__ == "__main__":
    main()

