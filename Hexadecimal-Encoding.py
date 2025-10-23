#!/usr/bin/env python3
import argparse

def selectively_hex_encode(payload, times=1):
    # Encode only < and > characters, up to 'times' times
    for _ in range(times):
        new_payload = []
        for c in payload:
            if c == '<':
                new_payload.append('%3C')
            elif c == '>':
                new_payload.append('%3E')
            else:
                new_payload.append(c)
        payload = ''.join(new_payload)
    return payload

def process_payloads(input_file, output_file, times):
    try:
        with open(input_file, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading payloads file: {e}")
        return

    try:
        with open(output_file, 'w') as f_out:
            for p in payloads:
                encoded = selectively_hex_encode(p, times)
                f_out.write(encoded + '\n')
        print(f"Processed {len(payloads)} payloads and saved to {output_file}")
    except Exception as e:
        print(f"Error writing output file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Convert only '<' and '>' in XSS payloads to %3C and %3E with multiple passes")
    parser.add_argument('-p', '--payloads', required=True, help="Input file containing XSS payloads")
    parser.add_argument('-o', '--output', required=True, help="Output file for encoded payloads")
    parser.add_argument('-e', '--encode-times', type=int, choices=[1, 2, 3], default=1,
                        help="Number of times to encode (1-3, default 1)")

    args = parser.parse_args()
    process_payloads(args.payloads, args.output, args.encode_times)

if __name__ == "__main__":
    main()

