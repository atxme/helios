# Fuzzing — §14.1

Le §14.1 de `docs/specification/ROTATION-CERTIFICATS.md` demande le fuzzing
« de tous les objets signés, de leurs certificats embarqués et de la machine
d'état temporelle ». Ce répertoire porte les cibles libFuzzer.

## Où vit le code

**Ici, presque rien.** Chaque cible est un `fuzz_target!` de trois lignes qui
appelle une fonction de `aether::fuzzing`. Tout le contenu — ce qui est
alimenté, ce qui est refusé, ce qui est *asserté* — est dans
`crates/aether/src/fuzzing.rs`.

C'est délibéré. libFuzzer exige une chaîne d'outils *nightly*, et du code que
seule une nightly compile est du code que personne n'exécute sur la branche qui
part en production. En plaçant les harnais dans `aether` :

- `cargo check` et `cargo clippy` les vérifient comme le reste ;
- `cargo test -p aether` les exécute sur une poignée de graines, si bien qu'un
  harnais qui a cessé de compiler — ou qui est devenu silencieusement inerte
  parce qu'un type a été renommé — échoue tout de suite, et non le jour où
  quelqu'un relance `cargo fuzz` après un mois ;
- ce répertoire reste **hors de l'espace de travail** (son `Cargo.toml` déclare
  un `[workspace]` vide), donc aucune commande ordinaire du projet n'hérite de
  l'exigence nightly.

## Les cibles

| Cible | Ce qu'elle éprouve |
| --- | --- |
| `signed_object` | Chaque variante de `TrustUpdateObject`, plus la campagne et le résultat de campagne, décodés depuis des octets arbitraires. Un document que le parseur laisse passer doit encore survivre à `fingerprint()`, qui reparcourt tous les champs qu'il a déclarés. |
| `trust_transaction` | L'assemblage chunké du §8.1.1 : des fragments s'assemblent en exactement la transaction que leur manifeste décrit, ou en rien. Un accumulateur partiel ne se déclare jamais complet ; un accumulateur complet rend exactement le nombre d'objets annoncé. |
| `x509_documents` | Le DER qui arrive **à l'intérieur** d'une enveloppe signée — le cas précis où « c'est signé » ne dit rien des octets, la signature ne couvrant que l'empreinte d'un certificat que personne n'a encore parsé. |
| `gateway_state_machine` | La machine d'état temporelle des §4 et §6, pilotée par une suite d'opérations arbitraires à des horloges arbitraires. C'est la cible qui paie : les autres vérifient qu'un parseur refuse, celle-ci vérifie qu'une suite d'opérations *d'apparence légale* ne peut pas mener l'état là où la spécification l'interdit. |
| `tunnel_addresses` | Hors §14.1 : les parseurs d'adresses du tunnel (`aether::net`, `ADRESSAGE-IPV6.md` §4), qui lisent un `network.toml` édité à la main. Une valeur acceptée se réécrit en un texte que le parseur relit comme la même valeur (octet pour octet pour un VIP IPv4), et un préfixe construit depuis n'importe quel Global ID n'accepte comme VIP de pair que les IID non exclus du §3.2. |

Les invariants assertés par `gateway_state_machine`, à chaque pas :

- un compteur de révocation consommé ne redescend jamais ;
- `revoked` est terminal — aucune passe d'entretien ne le lève ;
- un rollback de service ne déplace aucun compteur et ne survit jamais au
  chevauchement dans lequel il vit.

## Lancer

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

cd fuzz
cargo +nightly fuzz run gateway_state_machine
cargo +nightly fuzz run signed_object -- -max_total_time=300
```

Un refus est le résultat **attendu** : ces fonctions reçoivent des octets
contrôlés par un attaquant et leur métier est de dire non. Ce qu'aucune ne doit
faire, c'est paniquer.

## Limites connues

- **Aucune cible ne vérifie une signature valide.** Un fuzzer ne peut pas en
  produire une : ce qui est éprouvé est le décodage et l'ordre des contrôles
  qui précèdent la vérification, c'est-à-dire l'endroit où un document mal
  formé fait ses dégâts.
- **Il n'y a pas de corpus de graines versionné.** Les graines de
  `aether::fuzzing::tests` existent pour prouver que les harnais fonctionnent,
  pas pour guider un fuzzer ; celui-ci construit son propre corpus dans
  `fuzz/corpus/`, qui n'est pas suivi par Git. Un corpus issu de véritables
  documents signés accélérerait nettement la couverture, et reste à faire.
- **Rien de tout ceci n'a tourné sur cette branche.** L'environnement de
  développement n'a pas de nightly ; seules les fonctions de `aether::fuzzing`
  ont été compilées et exercées sur leurs graines. La première exécution
  réelle de `cargo fuzz` reste à faire.
