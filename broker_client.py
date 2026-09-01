"""Operator side of the OAuth broker: generate the keypair, collect the
sealed credential, decrypt it locally.

The private key is generated here and never leaves this machine. The broker
is given only the public half, so it can seal a token to the operator but can
never read one.

NOT WIRED TO ANYTHING DEPLOYED. `collect` takes an explicit fetcher so it can
be exercised offline; there is no default endpoint.

Usage:
    python broker_client.py keygen --private-out broker-operator.key
    # give the printed public key to the broker's configuration

    python broker_client.py collect --url https://.../pickup/<invite> \\
        --private broker-operator.key --token-out tokens/coach.json
"""
import argparse
import json
import os
import secrets
import sys
import urllib.parse

import broker_crypto


def keygen(private_path):
    """Create the operator keypair, writing the private half owner-only."""
    if os.path.exists(private_path):
        raise FileExistsError(
            f"{private_path} already exists; refusing to overwrite a private "
            "key. Move it aside if you really want a new one."
        )
    private_bytes, public_bytes = broker_crypto.generate_operator_keypair()

    parent = os.path.dirname(private_path)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(private_bytes.hex())
        handle.write("\n")
    os.chmod(private_path, 0o600)
    return public_bytes.hex()


def mint_invite():
    """Create one invite id offline.

    Deliberately not an HTTP endpoint and not a call into the running
    broker: the operator generates the id here, adds it to the broker's
    BROKER_INVITE_IDS, and restarts the instance. Nothing reachable over the
    network can create an invite, and there is no admin surface to defend.
    """
    return secrets.token_urlsafe(24)


def load_private_key(path):
    with open(path, encoding="ascii") as handle:
        return bytes.fromhex(handle.read().strip())


def collect(fetcher, private_key, token_out):
    """Fetch sealed bytes, decrypt locally, write the credential owner-only.

    `fetcher` returns the raw sealed bytes. It is injected so this can be
    tested without a network and so no default endpoint is baked in.
    """
    sealed = fetcher()
    if not sealed:
        raise ValueError("nothing to collect; the broker had no credential")

    plaintext = broker_crypto.unseal(private_key, sealed)
    document = json.loads(plaintext.decode("utf-8"))
    if not document.get("refresh_token"):
        raise ValueError("collected payload carried no refresh token")

    if os.path.exists(token_out):
        raise FileExistsError(
            f"{token_out} already exists; refusing to overwrite a credential"
        )
    parent = os.path.dirname(token_out)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    descriptor = os.open(token_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(token_out, 0o600)
    return token_out


def _http_fetcher(url, bearer):
    def fetch():
        import requests

        response = requests.get(
            url, headers={"Authorization": f"Bearer {bearer}"}, timeout=30
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"pickup failed with status {response.status_code}"
            )
        return response.content
    return fetch


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Operator side of the hosted OAuth broker."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("keygen", help="Create the operator keypair")
    generate.add_argument("--private-out", required=True)

    invite = sub.add_parser(
        "mint-invite",
        help="Create an invite id offline; add it to BROKER_INVITE_IDS",
    )
    invite.add_argument("--broker-url", default="",
                        help="Broker base URL, to print the full invite link")

    gather = sub.add_parser("collect", help="Fetch and decrypt a credential")
    gather.add_argument("--url", required=True)
    gather.add_argument("--private", required=True)
    gather.add_argument("--token-out", required=True)
    gather.add_argument("--bearer-env", default="BROKER_OPERATOR_BEARER",
                        help="Environment variable holding the bearer "
                             "credential; never pass it on the command line")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    if args.command == "keygen":
        try:
            public_hex = keygen(args.private_out)
        except FileExistsError as exc:
            print(f"keygen error: {exc}")
            return 1
        print(f"Private key written to {args.private_out} (mode 0600).")
        print("Keep it on this machine. The broker never receives it.\n")
        print("Give the broker this public key:")
        print(f"  BROKER_OPERATOR_PUBLIC_KEY={public_hex}")
        return 0

    if args.command == "mint-invite":
        invite_id = mint_invite()
        print("Invite id (single use):")
        print(f"  {invite_id}\n")
        print("1. Add it to the broker's environment, comma-separated with "
              "any others still outstanding:")
        print(f"     BROKER_INVITE_IDS={invite_id}")
        print("2. Restart the broker instance so it seeds the new invite.")
        if args.broker_url:
            base = args.broker_url.rstrip("/")
            print("3. Send the account owner this link:")
            print(f"     {base}/start/{urllib.parse.quote(invite_id)}")
        else:
            print("3. Send the owner:  https://<broker-host>/start/"
                  f"{invite_id}")
        print("\nThe link is single use. Its 24-hour TTL is an upper bound,")
        print("not a promise: on a free-plan instance an idle spin-down wipes")
        print("in-memory state, so have the owner sign in and collect the")
        print("credential in the same sitting.")
        return 0

    bearer = os.environ.get(args.bearer_env, "")
    if not bearer:
        print(f"{args.bearer_env} is not set; refusing to send an empty "
              "credential.")
        return 2
    try:
        path = collect(
            _http_fetcher(args.url, bearer),
            load_private_key(args.private),
            args.token_out,
        )
    except (ValueError, FileExistsError, RuntimeError,
            broker_crypto.SealError) as exc:
        print(f"collect error: {exc}")
        return 1
    print(f"Credential written to {path} (mode 0600).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
