#!/usr/bin/env python3
import argparse
import random

def random_case(payload):
    return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

def process_payloads(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            payloads = [line.rstrip('\n') for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading payloads file: {e}")
        return

    try:
        with open(output_file, 'w') as fout:
            for p in payloads:
                obf = random_case(p)
                fout.write(obf + '\n')
        print(f"Processed {len(payloads)} payloads and saved to {output_file}")
    except Exception as e:
        print(f"Error writing to output file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Convert payloads to random mixed case (e.g., <ScRiPt>)")
    parser.add_argument('-p', '--payloads', required=True, help="Input payload file")
    parser.add_argument('-o', '--output', required=True, help="Output file")

    args = parser.parse_args()
    process_payloads(args.payloads, args.output)

if __name__ == "__main__":
    main()
