#!/usr/bin/env python3
import argparse
import random

def whitespace_obfuscate(payload):
    # insert \n randomly between letters (only between letters, not before/after)
    new_payload = []
    for i, c in enumerate(payload):
        new_payload.append(c)
        # With 50% chance, and not at the last character, add \n after the character
        if i < len(payload) - 1 and c.isalpha() and random.choice([True, False]):
            new_payload.append('\\n')
    return ''.join(new_payload)

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
                obf = whitespace_obfuscate(p)
                fout.write(obf + '\n')
        print(f"Processed {len(payloads)} payloads with whitespace obfuscation and saved to {output_file}")
    except Exception as e:
        print(f"Error writing to output file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Convert payloads by inserting \\n randomly between letters (e.g. <scr\\nipt>)")
    parser.add_argument('-p', '--payloads', required=True, help="Input payload file")
    parser.add_argument('-o', '--output', required=True, help="Output file")

    args = parser.parse_args()
    process_payloads(args.payloads, args.output)

if __name__ == "__main__":
    main()
