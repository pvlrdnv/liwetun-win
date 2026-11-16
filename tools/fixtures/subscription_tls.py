"""Generate a fresh synthetic TLS fixture; never install a trust root."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--openssl', default='openssl')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    config = args.output / 'openssl.cnf'
    config.write_text('[req]\ndistinguished_name=dn\n[dn]\n', encoding='utf-8')
    subprocess.run([args.openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-sha256',
                    '-nodes', '-days', '1', '-config', str(config),
                    '-keyout', str(args.output / 'key.pem'),
                    '-out', str(args.output / 'cert.pem'),
                    '-subj', '/CN=subscription.example.invalid',
                    '-addext', 'subjectAltName=DNS:subscription.example.invalid',
                    '-addext', 'basicConstraints=critical,CA:TRUE',
                    '-addext', 'extendedKeyUsage=serverAuth'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=30)
    print('synthetic_tls_fixture_prepared:no_system_trust_changes')


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.SubprocessError):
        raise SystemExit('synthetic_tls_fixture_preparation_failed') from None
