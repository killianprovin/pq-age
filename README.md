# pq-age

Chiffrement de fichiers post-quantique hybride, en Rust.

## Crypto

| Couche | Algorithmes |
|--------|------------|
| Échange de clés | X25519 + ML-KEM-768 (hybride, HKDF-SHA256) |
| Chiffrement | ChaCha20-Poly1305 (streaming, chunks 64 Ko) |
| Signatures | Ed25519 + ML-DSA-65 (header signé) |

Le header contient le fingerprint du sender. Au déchiffrement, si le contact est connu, la signature est vérifiée automatiquement.

## Install

```
cargo install --path .
```

## Usage

```bash
# Générer une identité
pq-age key-gen

# Chiffrer (pour soi-même)
pq-age encrypt -i document.pdf

# Chiffrer pour quelqu'un
pq-age encrypt -i document.pdf -r alice

# Déchiffrer
pq-age decrypt -i document.pq
```

### Contacts

```bash
pq-age contacts list
pq-age contacts me                        # Afficher sa clé publique
pq-age contacts add alice -f alice.pub    # Depuis un fichier
pq-age contacts add alice                 # Coller la clé dans le terminal
pq-age contacts show alice
pq-age contacts remove alice
```

## Structure des clés

Tout est dans `~/.pq-age/` :

```
~/.pq-age/
├── identities.txt   # Clé privée (PQ-AGE-SECRET-KEY-1...)
├── recipient.pub     # Ta clé publique
└── recipients/       # Contacts connus
    ├── self.pub
    └── alice.pub
```

## Format du fichier `.pq`

```
version (1o) | eph_x25519 (32o) | mlkem_ct (1088o) | sender_fp (32o) | ed25519_sig (64o) | mldsa_sig (3309o) | payload chiffré
```

Header : 4526 octets. Le reste est du ChaCha20-Poly1305 en streaming.
