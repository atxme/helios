//! The command line: the arguments, their conversions and every subcommand.

use super::*;

#[derive(Parser)]
#[command(
    name = "astra-signer",
    version,
    about = "Compagnon opérateur d'Astra : ouvre le coffre d'autorité par une clé de sécurité \
             FIDO2 (ADR-008 §4)"
)]
pub(crate) struct Cli {
    /// Path of the encrypted vault. It is meant to be backed up.
    #[arg(long, env = "ASTRA_VAULT")]
    pub(crate) vault: Option<PathBuf>,
    /// Comment joindre la clé de sécurité.
    ///
    /// `platform` sous Windows : l'API du système, sans élévation, et c'est
    /// lui qui demande le PIN. `hid` parle CTAP2 directement — partout, mais
    /// sous Windows uniquement depuis un processus administrateur.
    ///
    /// Globale : elle est acceptée avant comme après la sous-commande, parce
    /// qu'un opérateur qui bascule de transport la tape naturellement à la fin
    /// de la ligne.
    #[arg(long, value_enum, global = true, default_value_t = TransportArg::default())]
    pub(crate) transport: TransportArg,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum TransportArg {
    /// L'API du système. Sans élévation ; le PIN est saisi par le système.
    #[cfg_attr(windows, default)]
    Platform,
    /// CTAP2 sur HID. Sous Windows, exige une console administrateur.
    #[cfg_attr(not(windows), default)]
    Hid,
}

impl From<TransportArg> for Transport {
    fn from(value: TransportArg) -> Self {
        match value {
            TransportArg::Platform => Transport::Platform,
            TransportArg::Hid => Transport::Hid,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum RoleArg {
    /// The key in daily use.
    Principale,
    /// A key kept elsewhere, whose only job is to survive the loss of another.
    Recuperation,
}

impl From<RoleArg> for SlotRole {
    fn from(value: RoleArg) -> Self {
        match value {
            RoleArg::Principale => SlotRole::Primary,
            RoleArg::Recuperation => SlotRole::Recovery,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum RevokedHalvesArg {
    Both,
    Tls,
    Pq,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum RevocationScopeArg {
    /// One admitted client's leaves.
    Client,
    /// The gateway's own leaves. Terminal for the whole domain's data plane.
    Gateway,
}

impl From<RevocationScopeArg> for aether::certificates::revocation::RevocationScope {
    fn from(value: RevocationScopeArg) -> Self {
        match value {
            RevocationScopeArg::Client => Self::Client,
            RevocationScopeArg::Gateway => Self::Gateway,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum AbortReasonArg {
    /// L'opérateur renonce à la transition qu'il a fait signer.
    OperatorCancelled,
    /// Une décision plus récente la remplace avant son activation.
    SupersededBeforeActivation,
}

impl From<AbortReasonArg> for aether::certificates::gateway::AbortReason {
    fn from(value: AbortReasonArg) -> Self {
        match value {
            AbortReasonArg::OperatorCancelled => Self::OperatorCancelled,
            AbortReasonArg::SupersededBeforeActivation => Self::SupersededBeforeActivation,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum RevocationReasonArg {
    KeyCompromise,
    SuspectedCompromise,
    Cessation,
    Superseded,
}

impl From<RevocationReasonArg> for aether::certificates::revocation::RevocationReason {
    fn from(value: RevocationReasonArg) -> Self {
        match value {
            RevocationReasonArg::KeyCompromise => Self::KeyCompromise,
            RevocationReasonArg::SuspectedCompromise => Self::SuspectedCompromise,
            RevocationReasonArg::Cessation => Self::Cessation,
            RevocationReasonArg::Superseded => Self::Superseded,
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Creates the vault around fresh anchors and registers the first key.
    Init {
        /// WebAuthn RP ID the credentials are registered under. The same value
        /// `astra bootstrap --webauthn-rp-id` is given: an assertion made
        /// under one RP ID does not answer under another.
        #[arg(long)]
        rp_id: String,
        /// Trust domain identifier, 32 hex characters. Drawn at random when
        /// left out, which is the ordinary case — the domain does not exist
        /// before this command.
        #[arg(long)]
        trust_domain_id: Option<String>,
        #[arg(long)]
        label: String,
        #[arg(long, value_enum, default_value = "principale")]
        role: RoleArg,
    },
    /// Registers another security key. Two devices, plugged one at a time.
    Enrol {
        #[arg(long)]
        label: String,
        #[arg(long, value_enum, default_value = "recuperation")]
        role: RoleArg,
    },
    /// Proves a security key opens the anchors.
    Verify,
    /// Prints the slot table and the state of the authority.
    List,
    /// Withdraws a security key, never the last recovery.
    Remove {
        /// Slot identifier, 32 hex characters, as `list` prints it.
        #[arg(long)]
        slot: String,
    },
    /// Liste les périphériques HID visibles, et lesquels sont des clés FIDO2.
    ///
    /// À lancer quand `init` annonce qu'aucune clé n'est branchée alors qu'elle
    /// l'est : une clé de sécurité se reconnaît à son usage page HID `0xF1D0`,
    /// et lire cette valeur demande d'ouvrir le périphérique — ce qu'un
    /// processus non élevé ne peut pas faire sous Windows.
    Devices,
    /// Réécrit le relais public à côté du coffre, et l'affiche.
    ///
    /// Needs no security key: everything in it is public, and it is read by a
    /// deployment that must never see the authority — and by every commande de
    /// signature ci-dessous, qui y lit la gateway, le nom de service et la clé
    /// de service Astra plutôt que de les faire retaper.
    Domain {
        /// Clé publique WireGuard de la gateway, base64.
        #[arg(long)]
        gateway_wg_public_key: Option<String>,
        /// Nom de service de la gateway, tel que la politique l'épingle.
        #[arg(long)]
        server_name: Option<String>,
        /// Clé publique de service d'Astra, base64, telle que `astra
        /// bootstrap` l'imprime. Épinglée : une demande d'approbation est
        /// vérifiée sous elle avant d'être montrée à un opérateur.
        #[arg(long)]
        astra_service_public_key: Option<String>,
        #[arg(long)]
        astra_service_key_epoch: Option<u64>,
        /// Origine que le domaine déclare, telle qu'`astra init-trust-domain`
        /// l'a enregistrée. Comparée à celle que nomme toute demande signée —
        /// et seule source de cette comparaison lorsque la campagne passe par
        /// le tunnel, où aucune URL n'est composée.
        #[arg(long)]
        astra_authority_url: Option<String>,
    },
    /// Auto-signe le certificat `CA-TLS` client autour de la clé du coffre.
    IssueCaTls {
        /// Durée de validité, en jours.
        #[arg(long, default_value_t = 3650)]
        days: u64,
        /// Où écrire le certificat en PEM, en plus du relais.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Signe une `AstraIssuerAuthorization` pour l'émetteur délégué d'Astra.
    ///
    /// Avec `--authority-url` et `--operation-id`, la demande est **récupérée**
    /// par les routes du §8.2 et la délégation y est redéposée : la campagne
    /// nomme l'époque et les deux clés exactes qui seront certifiées, et
    /// l'opérateur les lit avant le toucher. Une demande de délégation ne
    /// porte aucune signature — hors campagne, ce compagnon signe donc le
    /// fichier qu'on lui présente, et rien ne le rattache à une autorité.
    AuthorizeIssuer {
        /// Demande de délégation produite par `astra issuer request`, en JSON.
        ///
        /// Le fichier reste le transport, même en campagne : la campagne est
        /// ce qui l'authentifie, pas ce qui le porte.
        #[arg(long)]
        request: PathBuf,
        /// Où écrire l'autorisation signée, en JSON.
        ///
        /// Facultatif en campagne : la délégation est déposée sur l'autorité.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Origine HTTPS publique d'Astra, p. ex. https://astra.example.
        #[arg(long, requires = "operation_id")]
        authority_url: Option<String>,
        /// Opération à approuver, 32 caractères hexadécimaux.
        ///
        /// Imprimée par `astra issuer request --reason --requested-by`.
        #[arg(long, requires = "authority_url")]
        operation_id: Option<String>,
        /// Origine WebAuthn attendue. Par défaut `https://<rp_id>`.
        #[arg(long)]
        origin: Option<String>,
        /// Durée de la délégation, en jours.
        #[arg(long, default_value_t = 30)]
        days: u64,
        /// Plafond de durée d'une leaf émise sous cette délégation, en jours.
        #[arg(long, default_value_t = 90)]
        leaf_days: u64,
    },
    /// Réémet le document de credentials à partir de la table de key-slots.
    Bindings {
        /// Key-slot à marquer « perdue », 32 caractères hexadécimaux.
        ///
        /// Une clé qu'on ne retrouve pas mais qu'on n'a pas retirée : elle
        /// n'approuve plus rien, et son key-slot ouvre toujours le coffre.
        /// Retirer le key-slot la révoque, ce qui est définitif.
        #[arg(long)]
        lost: Vec<String>,
        /// Key-slot à remettre « active », 32 caractères hexadécimaux.
        #[arg(long)]
        active: Vec<String>,
    },
    /// Approuve un renouvellement client. N'ouvre pas le coffre.
    Approve {
        /// `AstraCredentialApprovalRequest` signée par Astra, en JSON.
        ///
        /// Hors tunnel seulement. Dans le tunnel, la demande se récupère.
        #[arg(long, conflicts_with_all = ["heliosd_url", "operation_id"])]
        request: Option<PathBuf>,
        /// Où écrire l'approbation, en JSON. Astra y ajoute sa signature.
        #[arg(long, conflicts_with_all = ["heliosd_url", "operation_id"])]
        out: Option<PathBuf>,
        /// API de la gateway **dans** WireGuard, p. ex. http://100.64.0.1:8080.
        ///
        /// Orion ne lance plus cet outil : sa cérémonie tourne dans l'IHM
        /// (§12.2). Ce transport reste pour un opérateur qui préfère la ligne
        /// de commande, et suppose que cet outil tourne sur la machine du
        /// client : les routes de renouvellement authentifient le pair par sa
        /// VIP source.
        #[arg(long, requires = "operation_id")]
        heliosd_url: Option<String>,
        /// Opération à approuver, 32 caractères hexadécimaux.
        #[arg(long, requires = "heliosd_url")]
        operation_id: Option<String>,
        /// Génération active telle que le consommateur la persiste.
        ///
        /// À défaut, celle que la demande annonce — ce qui suffit à un
        /// opérateur qui vient de la lire, et jamais à une vérification.
        #[arg(long)]
        active_generation: Option<u64>,
    },
    /// Approuve une campagne de rotation manuelle (spec §7.6).
    ApproveCampaign {
        /// `AstraRotationCampaign` en JSON.
        ///
        /// Hors ligne seulement. Avec `--authority-url`, la campagne se
        /// récupère et son approbation se dépose par les routes du §8.2.
        #[arg(long, conflicts_with_all = ["authority_url", "operation_id"])]
        campaign: Option<PathBuf>,
        /// Où écrire l'approbation, en JSON.
        #[arg(long, conflicts_with_all = ["authority_url", "operation_id"])]
        out: Option<PathBuf>,
        /// Origine HTTPS publique d'Astra, p. ex. https://astra.example.
        ///
        /// Le canal hors tunnel : c'est le cas que le relais in-tunnel ne
        /// couvre pas, un opérateur sur son propre poste, sans VIP que la
        /// gateway résoudrait.
        #[arg(long, requires = "operation_id")]
        authority_url: Option<String>,
        /// Opération à approuver, 32 caractères hexadécimaux.
        ///
        /// Imprimée par `astra campaign open` sur la machine qui fait tourner
        /// Astra.
        #[arg(long, requires = "authority_url")]
        operation_id: Option<String>,
        /// Origine WebAuthn signée d'Astra. À défaut, `https://` suivi du RP ID.
        #[arg(long)]
        origin: Option<String>,
    },
    /// Fait tourner `CA-PQ`, sous deux clés distinctes (spec §9.1).
    RotateCaPq {
        /// Où écrire la `CaTransition` signée, en JSON.
        #[arg(long)]
        out: PathBuf,
        /// Délai avant que la nouvelle ancre soit servie, en jours.
        #[arg(long, default_value_t = 1)]
        prepare_days: u64,
        /// Recouvrement pendant lequel les deux ancres vérifient, en jours.
        #[arg(long, default_value_t = 30)]
        overlap_days: u64,
        /// Origine publique d'Astra, pour rattacher la rotation à une campagne.
        ///
        /// Avec `--operation-id`, la rotation est l'exécution d'une campagne
        /// `trust_authorities` : l'approbation et l'objet signé partent dans
        /// le même dépôt, et Astra distribue la transition aux pairs. Sans
        /// elle, la rotation reste un fichier que personne ne consomme.
        #[arg(long)]
        authority_url: Option<String>,
        /// Identifiant imprimé par `astra campaign open --scope trust-authorities`.
        #[arg(long)]
        operation_id: Option<String>,
        /// Origine WebAuthn, si elle diffère de `https://<rp_id>`.
        #[arg(long)]
        origin: Option<String>,
    },
    /// Signs and deposits an emergency client revocation (spec §10).
    Revoke {
        #[arg(long)]
        authority_url: String,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        origin: Option<String>,
        #[arg(long, value_enum, default_value = "client")]
        scope: RevocationScopeArg,
        #[arg(long, value_enum, default_value = "both")]
        halves: RevokedHalvesArg,
        /// Signed cryptographic expiry printed by `astra revocation open`.
        ///
        /// A client generation retires both its leaves at once, so one value
        /// covers them. A gateway's two leaves are issued separately and do
        /// not share an expiry: name them with `--tls-not-after` and
        /// `--pq-not-after`, which override this one when given.
        #[arg(long)]
        not_after: Option<u64>,
        #[arg(long)]
        tls_not_after: Option<u64>,
        #[arg(long)]
        pq_not_after: Option<u64>,
        #[arg(long, value_enum, default_value = "key-compromise")]
        reason: RevocationReasonArg,
        /// La transition `emergency_replacement` que cette révocation autorise
        /// (§10.1), telle qu'elle a été signée.
        ///
        /// Sans elle, une gateway révoquée est terminale : plus aucune
        /// transition ne s'installe, sur aucun détenteur, et le service reste
        /// à terre jusqu'à ce que le domaine soit reconstruit. Le fichier est
        /// lu, pas l'empreinte saisie : une valeur retapée de travers laisse
        /// une gateway qui attend un document que plus personne ne peut
        /// produire.
        #[arg(long)]
        replacement_transition: Option<PathBuf>,
    },
    /// Émet hors ligne la première feuille PQ gateway sous `CA-PQ` (§13.1).
    ///
    /// Aucun registre Astra n'existe encore : la demande et la feuille
    /// voyagent par fichiers. Deux credentials distincts sont exigés parce
    /// que cette admission n'a aucune identité sortante pour prouver une
    /// continuité.
    IssueGatewayBootstrap {
        /// Demande publique exportée par `heliosd init-key-negotiation`.
        #[arg(long)]
        request: PathBuf,
        /// Où écrire la feuille PQ à rapporter à la gateway.
        #[arg(long)]
        out: PathBuf,
        /// Durée de vie de la feuille, en jours.
        #[arg(long, default_value_t = 365)]
        validity_days: u64,
    },
    /// Émet la feuille gateway suivante et signe sa transition (§11.1 étape 4).
    ///
    /// La gateway a scellé sa clé et exporté une demande ; cette commande
    /// l'émet sous `CA-PQ` et signe la décision qui l'installe. Elle ne change
    /// rien à l'identité servie : la transition porte sa propre fenêtre, et
    /// c'est `activation_at` qui bascule.
    ///
    /// Le fichier produit se rapporte sur la gateway, à
    /// `heliosd install-gateway-transition`.
    SignGatewayTransition {
        /// Origine publique d'Astra, pour un opérateur sans tunnel (§8.2).
        #[arg(long, conflicts_with = "heliosd_url")]
        authority_url: Option<String>,
        /// API de la gateway dans le tunnel, chemin prioritaire (§8.5).
        #[arg(long, conflicts_with = "authority_url")]
        heliosd_url: Option<String>,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        origin: Option<String>,
        /// La demande exportée par `heliosd prepare-gateway-certificate`.
        #[arg(long)]
        request: PathBuf,
        /// La feuille PQ en service, exportée par `astra gateway-identity open`.
        ///
        /// Elle vérifie la signature de continuité du §5 — la preuve que la
        /// demande vient bien de l'identité en place. Absente, la continuité
        /// n'est pas vérifiée et `--key-recovery` doit être explicite.
        #[arg(long)]
        active_certificate: Option<PathBuf>,
        /// La feuille TLS candidate de la gateway, en DER.
        #[arg(long)]
        tls_certificate: Option<PathBuf>,
        /// Où écrire la transition signée.
        #[arg(long)]
        out: PathBuf,
        /// Durée de vie de la nouvelle feuille, en jours.
        #[arg(long, default_value_t = 365)]
        validity_days: u64,
        /// Délai avant `activation_at`, en jours : le temps laissé au parc
        /// pour recevoir la décision avant qu'elle prenne effet.
        #[arg(long, default_value_t = 7)]
        prepare_days: u64,
        /// Recouvrement entre `activation_at` et le retrait, en jours.
        #[arg(long, default_value_t = 7)]
        overlap_days: u64,
        /// La demande n'a pas de signature de continuité (§5, clé perdue).
        #[arg(long)]
        key_recovery: bool,
        /// Remplace une identité **révoquée** (§6.1, motif
        /// `emergency_replacement`).
        ///
        /// La transition produite n'est acceptée que par une gateway révoquée
        /// dont la révocation nomme ce document exact, et elle est alors
        /// servie immédiatement : il n'y a plus d'identité sortante avec
        /// laquelle se recouvrir. La signer avant la révocation, qui la
        /// nommera par `astra-signer revoke --replacement-transition`.
        #[arg(long)]
        emergency_replacement: bool,
    },
    /// Fait tourner la CA TLS cliente sous `CA-PQ` (§9.4).
    ///
    /// L'ancre entrante est créée ici, auto-signée pour prouver qu'elle
    /// détient sa clé, et la transition qui l'installe est signée par `CA-PQ`
    /// — laquelle ne bouge pas. Le coffre scelle la clé suivante *à côté* de
    /// celle qui émet : c'est `promote-ca-tls` qui les échange à
    /// `activation_at`, puis détruit l'ancienne au retrait.
    RotateCaTls {
        /// Origine publique d'Astra, pour un opérateur sans tunnel (§8.2).
        #[arg(long, conflicts_with = "heliosd_url")]
        authority_url: Option<String>,
        /// API de la gateway dans le tunnel, chemin prioritaire (§8.5).
        #[arg(long, conflicts_with = "authority_url")]
        heliosd_url: Option<String>,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        origin: Option<String>,
        /// Où écrire la transition signée, pour la porter sur la gateway.
        #[arg(long)]
        out: PathBuf,
        /// Délai avant `activation_at`, en jours.
        #[arg(long, default_value_t = 7)]
        prepare_days: u64,
        /// Recouvrement pendant lequel les deux ancres sont acceptées.
        #[arg(long, default_value_t = 30)]
        overlap_days: u64,
        /// Durée de vie de l'ancre entrante, en jours.
        #[arg(long, default_value_t = 1825)]
        validity_days: u64,
    },
    /// Rejoue le dépôt d'une rotation préparée mais jamais déposée.
    ///
    /// La cérémonie écrit sa décision avant d'en parler à quiconque. Si la
    /// machine s'est arrêtée entre l'écriture et le dépôt, ceci renvoie les
    /// mêmes octets : Astra traite un résultat identique comme le même, et
    /// aucune clé n'est redemandée — la décision a déjà été approuvée.
    ResumeRotation {
        /// Origine publique d'Astra, pour un opérateur sans tunnel (§8.2).
        #[arg(long, conflicts_with = "heliosd_url")]
        authority_url: Option<String>,
        /// API de la gateway dans le tunnel, chemin prioritaire (§8.5).
        #[arg(long, conflicts_with = "authority_url")]
        heliosd_url: Option<String>,
    },
    /// Signe un rollback de service vers l'ancienne identité gateway (§4.4).
    ///
    /// Pendant le recouvrement uniquement, et sans rien déplacer : aucun
    /// compteur ne bouge, le slot suivant reste scellé, et sa promotion a lieu
    /// à `not_after` comme prévu. La sélection expire d'elle-même, au plus tard
    /// avec le recouvrement.
    ///
    /// Hors campagne Astra, délibérément : un rollback ne distribue rien et ne
    /// change aucun état du domaine. La campagne est résolue localement depuis
    /// la transition elle-même, affichée, et attestée par une clé autorisée.
    SignGatewayRollback {
        /// La transition en recouvrement, telle qu'elle a été signée.
        #[arg(long)]
        transition: PathBuf,
        /// Où écrire l'autorisation signée.
        #[arg(long)]
        out: PathBuf,
        /// Durée de la sélection, en heures. Bornée par `not_after`.
        #[arg(long, default_value_t = 24)]
        hours: u64,
        /// Motif, affiché avant le toucher et scellé dans la campagne.
        #[arg(long)]
        reason: String,
        /// Qui demande, affiché avant le toucher.
        #[arg(long)]
        requested_by: String,
        #[arg(long)]
        origin: Option<String>,
    },
    /// Referme la fenêtre de rotation CA-TLS à `not_after` (§9.2).
    ///
    /// Une seule écriture scellée : la clé suivante devient celle qui émet et
    /// l'ancienne clé privée cesse d'exister. Pendant tout le recouvrement,
    /// l'autorité émet sous l'ancre sortante — la gateway compare
    /// `ca_tls_epoch` à l'identique et ne l'avance qu'à `not_after`. Appelée
    /// trop tôt, la commande n'écrit rien et dit quelle seconde elle attend.
    ///
    /// Limite connue : rien ne la lance à `not_after`. Cet outil attend
    /// l'opérateur, et émet sous l'ancienne époque jusque-là. Orion affiche
    /// « Terminer la rotation CA TLS » dès `not_after`, à l'ouverture de son
    /// onglet : c'est son rappel, et le recours de cette commande.
    PromoteCaTls,
    /// Signe l'annulation d'une transition gateway en attente (§6.3).
    ///
    /// Refusée une fois la transition distribuée ou `activation_at` atteint :
    /// un client peut déjà l'avoir persistée, repartir hors ligne et
    /// promouvoir seul. L'époque reste consommée.
    AbortGatewayTransition {
        /// Origine publique d'Astra, pour un opérateur sans tunnel (§8.2).
        #[arg(long, conflicts_with = "heliosd_url")]
        authority_url: Option<String>,
        /// API de la gateway dans le tunnel, chemin prioritaire (§8.5).
        #[arg(long, conflicts_with = "authority_url")]
        heliosd_url: Option<String>,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        origin: Option<String>,
        /// La transition à annuler, telle qu'elle a été signée.
        #[arg(long)]
        transition: PathBuf,
        /// Où écrire l'avortement signé.
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_enum, default_value = "operator-cancelled")]
        reason: AbortReasonArg,
    },
    /// Approuve la récupération d'une identité expirée (§7.5).
    ///
    /// Une seule commande, une seule clé branchée : elle lit la demande,
    /// l'affiche, prend l'assertion de l'opérateur, ouvre le coffre, émet les
    /// deux feuilles sous `CA-PQ` et `CA-TLS`, dépose l'autorisation, attend le
    /// reçu de la gateway et signe le grant. Le client, lui, n'a aucun tunnel :
    /// c'est ce que cette procédure répare.
    Recover {
        /// Origine publique d'Astra.
        #[arg(long)]
        authority_url: String,
        /// Identifiant imprimé par le client au moment où il a demandé.
        #[arg(long)]
        operation_id: String,
        /// Origine WebAuthn, si elle diffère de `https://<rp_id>`.
        #[arg(long)]
        origin: Option<String>,
    },
    /// Enrôle un client sans qu'aucune clé privée ne voyage (NEGOCIATION-DE-CLE-V5 §15).
    ///
    /// `invite` émet l'invitation à remettre au client ; `accept` vérifie sa
    /// demande, consomme l'invitation puis émet ses deux feuilles ;
    /// `sign-document` signe le `.orion` que `helios enroll document` a
    /// préparé. Le registre des invitations est sous
    /// `~/.helios/enrollment-invitations`, ou `$HELIOS_ENROLLMENT_REGISTRY`.
    Enroll {
        #[command(subcommand)]
        command: EnrollCommand,
    },
    /// Renames a slot. Needs no security key.
    Rename {
        #[arg(long)]
        slot: String,
        #[arg(long)]
        label: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum EnrollCommand {
    /// Signe sous `CA-PQ` une invitation à usage unique pour cette gateway.
    ///
    /// Une clé suffit ; deux credentials distincts avec `--allow-readmission`.
    /// L'empreinte `CA-PQ` affichée est celle que le client doit confirmer
    /// hors bande avant de créer sa demande.
    Invite {
        /// Feuille PQ servie par la gateway (JSON), celle qu'Orion épinglera.
        #[arg(long)]
        gateway_certificate: PathBuf,
        /// Durée de vie de l'invitation, en heures (24 au plus).
        #[arg(long, default_value_t = 24, value_parser = clap::value_parser!(u64).range(1..=24))]
        valid_for_hours: u64,
        /// Autorise la réadmission d'une clé WireGuard déjà enrôlée.
        #[arg(long)]
        allow_readmission: bool,
        /// Fichier `.helios-invite` à remettre au client.
        #[arg(long)]
        out: PathBuf,
    },
    /// Vérifie une demande, consomme son invitation, puis émet les feuilles.
    Accept {
        /// Fichier `.helios-request` reçu du client.
        #[arg(long)]
        request: PathBuf,
        /// Durée de vie des deux feuilles clientes, en jours.
        #[arg(long, default_value_t = 365)]
        validity_days: u64,
        /// Répertoire où écrire les deux feuilles.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Signe sous `CA-PQ` le brouillon de document `.orion`.
    SignDocument {
        /// Brouillon écrit par `helios enroll document`.
        #[arg(long)]
        draft: PathBuf,
        /// Document `.orion` signé, à remettre au client.
        #[arg(long)]
        out: PathBuf,
    },
    /// Liste les invitations et leur état. Ne demande aucune clé.
    List,
    /// Révoque une invitation encore émise. Ne demande aucune clé.
    Revoke {
        /// Identifiant de l'invitation, 32 caractères hexadécimaux.
        invitation_id: String,
    },
}
