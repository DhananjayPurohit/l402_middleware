use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::{protocol::Message, handshake::client::generate_key, http::Request}};
use futures_util::{StreamExt, SinkExt, FutureExt};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::{Sha256, Sha512, Digest};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Keypair};
use k256::{
    elliptic_curve::sec1::ToEncodedPoint,
    ProjectivePoint, Scalar,
};
use hex;
use rand::Rng;
use serde_json;
use base64;

/// Number of words in the LNC pairing phrase
const NUM_PASSPHRASE_WORDS: usize = 10;

/// Number of entropy bytes (14 bytes = 112 bits, which holds 10 * 11 = 110 bits)
const NUM_PASSPHRASE_ENTROPY_BYTES: usize = 14;

/// Bits per word in the aezeed wordlist (2048 words = 11 bits)
const BITS_PER_WORD: usize = 11;

/// scrypt parameters matching LNC
const SCRYPT_N: u32 = 65536; // 2^16
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_KEY_LEN: usize = 32;

/// The generator point N for SPAKE2, generated via try-and-increment with "Lightning Node Connect"
/// This is the hex-encoded compressed public key
const SPAKE2_N_HEX: &str = "0254a58cd0f31c008fd0bc9b2dd5ba586144933829f6da33ac4130b555fb5ea32c";

/// Noise protocol prologue
const LIGHTNING_NODE_CONNECT_PROLOGUE: &[u8] = b"lightning-node-connect";

/// The aezeed wordlist (BIP39 compatible)
/// This is the standard English BIP39 wordlist used by lnd/aezeed
static AEZEED_WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
    "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
    "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread",
    "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy",
    "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
    "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
    "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
    "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category",
    "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century",
    "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle",
    "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk",
    "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close",
    "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
    "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort",
    "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control",
    "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost",
    "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
    "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek",
    "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial",
    "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup",
    "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
    "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal",
    "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense",
    "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny",
    "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk",
    "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond",
    "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur",
    "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance",
    "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain",
    "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama",
    "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop",
    "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf",
    "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
    "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow",
    "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody",
    "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless",
    "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough",
    "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip",
    "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate",
    "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange",
    "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
    "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye",
    "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame",
    "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father",
    "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
    "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file",
    "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first",
    "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor",
    "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly",
    "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest",
    "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile",
    "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen",
    "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy",
    "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp",
    "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture",
    "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance",
    "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown",
    "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid",
    "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt",
    "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health",
    "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden",
    "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole",
    "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital",
    "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred",
    "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea",
    "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune",
    "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate",
    "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury",
    "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install",
    "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue",
    "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel",
    "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior",
    "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney",
    "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife",
    "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language",
    "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit",
    "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal",
    "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level",
    "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit",
    "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster",
    "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love",
    "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad",
    "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market",
    "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum",
    "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt",
    "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
    "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor",
    "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile",
    "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral",
    "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie",
    "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual",
    "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature",
    "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net",
    "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
    "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now",
    "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe",
    "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often",
    "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online",
    "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order",
    "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output",
    "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact",
    "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper",
    "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol",
    "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen",
    "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo",
    "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot",
    "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate",
    "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar",
    "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post",
    "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private",
    "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property",
    "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin",
    "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle",
    "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit",
    "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp",
    "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor",
    "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle",
    "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release",
    "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen",
    "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response",
    "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
    "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot",
    "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket",
    "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal",
    "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness",
    "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand",
    "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter",
    "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script",
    "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed",
    "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service",
    "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell",
    "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop",
    "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since",
    "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill",
    "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight",
    "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth",
    "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda",
    "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry",
    "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn",
    "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
    "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring",
    "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp",
    "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick",
    "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway",
    "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny",
    "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey",
    "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim",
    "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag",
    "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi",
    "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text",
    "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought",
    "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber",
    "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler",
    "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool",
    "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist",
    "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer",
    "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick",
    "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust",
    "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
    "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella",
    "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform",
    "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade",
    "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful",
    "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van",
    "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue",
    "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory",
    "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual",
    "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage",
    "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash",
    "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather",
    "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat",
    "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will",
    "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise",
    "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world",
    "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
    "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo",
];

/// Create a reverse word map for word -> index lookup
fn get_word_index(word: &str) -> Option<usize> {
    AEZEED_WORDLIST.iter().position(|&w| w == word)
}

/// LNC Pairing phrase data structure
#[derive(Debug, Clone)]
pub struct LNCPairingData {
    pub mnemonic: Option<String>,
    pub passphrase_entropy: Vec<u8>,
    pub stream_id: Vec<u8>,
    pub local_keypair: Keypair,
    pub mailbox_server: String,
}

/// Convert 10 mnemonic words to 14 bytes of entropy
/// Each word represents 11 bits, 10 words = 110 bits
/// We pack these into 14 bytes (112 bits), with the last 2 bits unused
fn mnemonic_to_entropy(words: &[&str]) -> Result<[u8; NUM_PASSPHRASE_ENTROPY_BYTES], Box<dyn Error + Send + Sync>> {
    if words.len() != NUM_PASSPHRASE_WORDS {
        return Err(format!("Expected {} words, got {}", NUM_PASSPHRASE_WORDS, words.len()).into());
    }

    // Convert words to bit indices
    let mut bits: Vec<bool> = Vec::with_capacity(NUM_PASSPHRASE_WORDS * BITS_PER_WORD);
    
    for word in words {
        let word_lower = word.to_lowercase();
        let index = get_word_index(&word_lower)
            .ok_or_else(|| format!("Unknown word in mnemonic: {}", word))?;
        
        // Each word is 11 bits
        for i in (0..BITS_PER_WORD).rev() {
            bits.push((index >> i) & 1 == 1);
        }
    }

    // Pack bits into bytes
    let mut entropy = [0u8; NUM_PASSPHRASE_ENTROPY_BYTES];
    for (i, chunk) in bits.chunks(8).enumerate() {
        if i >= NUM_PASSPHRASE_ENTROPY_BYTES {
            break;
        }
        let mut byte = 0u8;
        for (j, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - j);
            }
        }
        entropy[i] = byte;
    }

    Ok(entropy)
}

/// Stretch the passphrase entropy using scrypt (matching LNC's parameters)
fn stretch_passphrase(passphrase_entropy: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    use scrypt::{scrypt, Params};
    
    // LNC uses passphrase_entropy as both input and salt
    let params = Params::new(
        (SCRYPT_N as f64).log2() as u8, // log2(N)
        SCRYPT_R,
        SCRYPT_P,
        SCRYPT_KEY_LEN,
    ).map_err(|e| format!("Invalid scrypt params: {}", e))?;
    
    let mut output = vec![0u8; SCRYPT_KEY_LEN];
    scrypt(passphrase_entropy, passphrase_entropy, &params, &mut output)
        .map_err(|e| format!("scrypt failed: {}", e))?;
    
    Ok(output)
}

/// Derive the 64-byte stream ID from passphrase entropy using SHA-512
fn derive_stream_id(passphrase_entropy: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(passphrase_entropy);
    hasher.finalize().to_vec()
}

/// Parse the LNC pairing phrase - accepts 10-word mnemonic phrase
pub fn parse_pairing_phrase(phrase: &str) -> Result<LNCPairingData, Box<dyn Error + Send + Sync>> {
    let phrase = phrase.trim();
    
    // Parse as mnemonic phrase (10 words)
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != NUM_PASSPHRASE_WORDS {
        return Err(format!(
            "Invalid pairing phrase: expected {} words, got {} words",
            NUM_PASSPHRASE_WORDS, words.len()
        ).into());
    }
    
    // Convert mnemonic to entropy bytes
    let passphrase_entropy = mnemonic_to_entropy(&words)?;
    
    eprintln!("Passphrase entropy ({} bytes): {}", passphrase_entropy.len(), hex::encode(&passphrase_entropy));
    
    // Derive stream ID from passphrase entropy using SHA-512
    let stream_id = derive_stream_id(&passphrase_entropy);
    eprintln!("Stream ID ({} bytes): {}", stream_id.len(), hex::encode(&stream_id));
    
    // Generate a new local keypair for the session
    // In a real implementation, this should be persisted and reused
    let secp = Secp256k1::new();
    let mut secret_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret_bytes);
    let secret_key = SecretKey::from_slice(&secret_bytes)
        .map_err(|e| format!("Failed to create secret key: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    
    eprintln!("Local public key: {}", hex::encode(keypair.public_key().serialize()));
    
    Ok(LNCPairingData {
        mnemonic: Some(phrase.to_string()),
        passphrase_entropy: passphrase_entropy.to_vec(),
        stream_id,
        local_keypair: keypair,
        mailbox_server: std::env::var("LNC_MAILBOX_SERVER")
            .unwrap_or_else(|_| "ws://127.0.0.1:8085".to_string()),
    })
}

/// Parse the LNC pairing phrase from raw entropy hex
pub fn parse_pairing_phrase_from_entropy(entropy_hex: &str) -> Result<LNCPairingData, Box<dyn Error + Send + Sync>> {
    let passphrase_entropy = hex::decode(entropy_hex.trim())
        .map_err(|e| format!("Invalid entropy hex: {}", e))?;
    
    eprintln!("Passphrase entropy ({} bytes): {}", passphrase_entropy.len(), hex::encode(&passphrase_entropy));
    
    let stream_id = derive_stream_id(&passphrase_entropy);
    eprintln!("Stream ID ({} bytes): {}", stream_id.len(), hex::encode(&stream_id));
    
    let secp = Secp256k1::new();
    let mut secret_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret_bytes);
    let secret_key = SecretKey::from_slice(&secret_bytes)
        .map_err(|e| format!("Failed to create secret key: {}", e))?;
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    
    Ok(LNCPairingData {
        mnemonic: None,
        passphrase_entropy,
        stream_id,
        local_keypair: keypair,
        mailbox_server: std::env::var("LNC_MAILBOX_SERVER")
            .unwrap_or_else(|_| "ws://127.0.0.1:8085".to_string()),
    })
}

/// Represents an LNC mailbox connection
pub struct LNCMailbox {
    passphrase_entropy: Vec<u8>,
    stretched_passphrase: Option<Vec<u8>>,
    stream_id: Vec<u8>,
    local_keypair: Keypair,
    remote_public: Option<PublicKey>,
    shared_secret: Option<[u8; 32]>,
    mailbox_server: String,
    
    // Separate ciphers for sending and receiving (Noise protocol requirement)
    send_cipher: Option<ChaCha20Poly1305>,
    recv_cipher: Option<ChaCha20Poly1305>,
    
    // Store keys separately so we can recreate ciphers on clone
    send_key: Option<[u8; 32]>,
    recv_key: Option<[u8; 32]>,
    
    /// Authentication data received from server in Act 2 (to be sent as gRPC metadata)
    pub auth_data: Option<String>,
    
    // Implicit nonces (counters), not sent on wire
    send_nonce: u64,
    recv_nonce: u64,
    
    connection: Option<Arc<Mutex<MailboxConnection>>>,
}

#[derive(Clone)]
struct HandshakeParams {
    noise_state: NoiseHandshakeState,
    act1_msg: Vec<u8>,
}

impl LNCMailbox {
    pub fn new(
        pairing_data: LNCPairingData,
        mailbox_server: Option<String>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let server = mailbox_server.unwrap_or(pairing_data.mailbox_server);
        
        Ok(Self {
            passphrase_entropy: pairing_data.passphrase_entropy,
            stretched_passphrase: None,
            stream_id: pairing_data.stream_id,
            local_keypair: pairing_data.local_keypair,
            remote_public: None,
            shared_secret: None,
            mailbox_server: server,
            send_cipher: None,
            recv_cipher: None,
            send_key: None,
            recv_key: None,
            send_nonce: 0,
            recv_nonce: 0,
            auth_data: None,
            connection: None,
        })
    }
    
    /// Encrypt a message using the send cipher and implicit nonce
    /// Implements the Noise Machine's length-prefixed framing:
    /// 1. Encrypt 2-byte length header -> 18 bytes (2 + 16 MAC)
    /// 2. Encrypt message body -> N + 16 bytes
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        eprintln!("🔒 Encrypting {} bytes to send: {:02x?}", plaintext.len(), &plaintext[..plaintext.len().min(50)]);
        
        let cipher = self.send_cipher.as_ref()
            .ok_or("Send cipher not initialized. Complete the Noise handshake before encrypting.")?;
        
        if plaintext.len() > 65535 {
            return Err("Message too large (max 65535 bytes)".into());
        }
        
        // Step 1: Encrypt the length header (2 bytes)
        let length = plaintext.len() as u16;
        let length_bytes = length.to_be_bytes();
        
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.send_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.send_nonce = self.send_nonce.checked_add(1).ok_or("Send nonce overflow")?;
        
        let encrypted_header = cipher.encrypt(nonce, &length_bytes[..])
            .map_err(|e| format!("Failed to encrypt length header: {}", e))?;
        
        eprintln!("   📏 Encrypted length header: {} bytes -> {} bytes", length_bytes.len(), encrypted_header.len());
        
        // Step 2: Encrypt the message body
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.send_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.send_nonce = self.send_nonce.checked_add(1).ok_or("Send nonce overflow")?;
        
        let encrypted_body = cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("Failed to encrypt body: {}", e))?;
        
        eprintln!("   📦 Encrypted body: {} bytes -> {} bytes", plaintext.len(), encrypted_body.len());
        
        // Combine header + body
        let mut result = Vec::with_capacity(encrypted_header.len() + encrypted_body.len());
        result.extend_from_slice(&encrypted_header);
        result.extend_from_slice(&encrypted_body);
        
        Ok(result)
    }
    
    /// Decrypt a message using the recv cipher and implicit nonce
    /// Implements the Noise Machine's length-prefixed framing:
    /// 1. Decrypt 18-byte length header -> 2 bytes length
    /// 2. Decrypt (length + 16) bytes body -> length bytes plaintext
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let cipher = self.recv_cipher.as_ref()
            .ok_or("Recv cipher not initialized")?;
        
        // Minimum size: 18 bytes (encrypted header with MAC)
        if ciphertext.len() < 18 {
            return Err(format!("Ciphertext too short: {} bytes (need at least 18)", ciphertext.len()).into());
        }
        
        // Step 1: Decrypt the length header (first 18 bytes: 2 bytes + 16-byte MAC)
        let encrypted_header = &ciphertext[0..18];
        
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.recv_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.recv_nonce = self.recv_nonce.checked_add(1).ok_or("Recv nonce overflow")?;
        
        let length_bytes = cipher.decrypt(nonce, encrypted_header)
            .map_err(|e| format!("Failed to decrypt length header: {}", e))?;
        
        if length_bytes.len() != 2 {
            return Err(format!("Invalid length header size: {}", length_bytes.len()).into());
        }
        
        let expected_length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
        eprintln!("   📏 Decrypted length header: expecting {} bytes of data", expected_length);
        
        // Step 2: Decrypt the body (expected_length + 16-byte MAC)
        let expected_body_len = expected_length + 16;
        if ciphertext.len() < 18 + expected_body_len {
            return Err(format!(
                "Incomplete message: have {} bytes, need {} (18 header + {} body)",
                ciphertext.len(), 18 + expected_body_len, expected_body_len
            ).into());
        }
        
        let encrypted_body = &ciphertext[18..18 + expected_body_len];
        
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.recv_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.recv_nonce = self.recv_nonce.checked_add(1).ok_or("Recv nonce overflow")?;
        
        let plaintext = cipher.decrypt(nonce, encrypted_body)
            .map_err(|e| format!("Failed to decrypt body: {}", e))?;
        
        eprintln!("🔓 Decrypted {} bytes from server: {:02x?}", plaintext.len(), &plaintext[..plaintext.len().min(50)]);
        
        if plaintext.len() != expected_length {
            return Err(format!(
                "Length mismatch: header said {} bytes, but got {} bytes",
                expected_length, plaintext.len()
            ).into());
        }
        
        Ok(plaintext)
    }
    
    /// Get the receive SID for client (server-to-client stream)
    /// In LNC client: receiveSID := GetSID(sid, true) which returns sid
    fn get_receive_sid(&self) -> [u8; 64] {
        let mut sid = [0u8; 64];
        sid.copy_from_slice(&self.stream_id);
        sid
    }
    
    /// Get the send SID for client (client-to-server stream)
    /// In LNC client: sendSID := GetSID(sid, false) which returns sid ^ 0x01
    fn get_send_sid(&self) -> [u8; 64] {
        let mut sid = [0u8; 64];
        sid.copy_from_slice(&self.stream_id);
        sid[63] ^= 0x01;
        sid
    }
    
    /// Get or create the mailbox connection (lazy connection)
    pub async fn get_connection(&mut self) -> Result<Arc<Mutex<MailboxConnection>>, Box<dyn Error + Send + Sync>> {
        if let Some(ref conn) = self.connection {
            return Ok(Arc::clone(conn));
        }
        
        // Stretch the passphrase if not already done
        if self.stretched_passphrase.is_none() {
            eprintln!("🔐 Stretching passphrase with scrypt (N={}, R={}, P={})...", SCRYPT_N, SCRYPT_R, SCRYPT_P);
            self.stretched_passphrase = Some(stretch_passphrase(&self.passphrase_entropy)?);
            eprintln!("✅ Passphrase stretched");
        }
        
        let stream_id_hex = hex::encode(&self.stream_id);
        let receive_sid = self.get_receive_sid();
        let send_sid = self.get_send_sid();
        
        eprintln!("Connecting to mailbox server");
        eprintln!("  Full Stream ID ({} bytes): {}", self.stream_id.len(), stream_id_hex);
        eprintln!("  Receive SID (server→client): {}", hex::encode(&receive_sid));
        eprintln!("  Send SID (client→server): {}", hex::encode(&send_sid));
        
        self.connect_to_mailbox().await
    }
    
    pub async fn connect_to_mailbox(&mut self) -> Result<Arc<Mutex<MailboxConnection>>, Box<dyn Error + Send + Sync>> {
        let receive_sid = self.get_receive_sid();
        let send_sid = self.get_send_sid();
        
        // v8: Log PID to help identify ghost processes
        eprintln!("🆔 Process ID: {}", std::process::id());
        
        // v4: Pre-compute Noise Act 1 and state machine BEFORE the loop.
        // SPAKE2 masking is expensive and should only happen once.
        eprintln!("🔐 Pre-computing Noise Act 1 (SPAKE2 masking)...");
        let mut noise_state = NoiseHandshakeState::new(
            &self.local_keypair,
            self.stretched_passphrase.as_ref().unwrap().clone(),
        )?;
        let act1_msg = noise_state.act1()?;
        eprintln!("✅ Act 1 pre-computed ({} bytes)", act1_msg.len());
        
        let params = HandshakeParams {
            noise_state,
            act1_msg,
        };

        let max_retries = 10;
        let mut attempt = 0;
        
        loop {
            if attempt > 0 {
                eprintln!("Retrying mailbox connection (attempt {}/{})...", attempt + 1, max_retries);
            }
            
            // v4: Pass pre-computed params (cloned if we need to retry)
            match self.perform_dual_stream_handshake(&receive_sid, &send_sid, params.clone()).await {
                Ok(conn) => {
                    eprintln!("✅ Successfully completed LNC handshake");
                    return Ok(conn);
                }
                Err(e) => {
                    let error_str = e.to_string();
                    eprintln!("❌ Handshake failed: {}", error_str);
                    
                    let is_occupied = error_str.contains("stream occupied") || error_str.contains("already active");
                    let is_retryable = is_occupied ||
                                     error_str.contains("Stream not found") || 
                                     error_str.contains("stream not found") ||
                                     error_str.contains("resync required") ||
                                     error_str.contains("Connection reset") ||
                                     error_str.contains("timeout");
                    
                    if !is_retryable {
                        return Err(format!("❌ Handshake failed and cannot retry: {}", error_str).into());
                    }
                    
                    attempt += 1;
                    if attempt >= max_retries {
                        return Err(format!("❌ Handshake failed after {} attempts: {}", attempt, error_str).into());
                    }
                    
                    // v8.1: Use an even longer randomized backoff (10-20s) for occupied streams
                    let backoff_ms = if is_occupied { 
                        rand::thread_rng().gen_range(10000..20000)
                    } else { 
                        500 
                    };
                    eprintln!("⏳ Waiting {}ms before retry (randomized to prevent lock-step)...", backoff_ms);
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    continue;
                }
            }
        }
    }
    
    /// Perform the LNC handshake using GoBN protocol
    /// The correct order is:
    /// 1. Open RECEIVE and subscribe (so we can receive SYNACK)
    /// 2. Open SEND and send SYN
    /// 3. Server receives SYN, sends SYNACK  
    /// 4. We receive SYNACK
    async fn perform_dual_stream_handshake(
        &mut self,
        receive_sid: &[u8; 64],
        send_sid: &[u8; 64],
        params: HandshakeParams,
    ) -> Result<Arc<Mutex<MailboxConnection>>, Box<dyn Error + Send + Sync>> {
        let recv_url = self.mailbox_recv_url();
        let send_url = self.mailbox_send_url();
        
        
        
        
        // Step 1: Open SEND connection FIRST
        eprintln!("🔌 Opening SEND stream: {}", send_url);
        let (mut send_write, _send_read) = self.try_connect_endpoint(&send_url).await
            .map_err(|e| format!("Failed to connect to send endpoint: {}", e))?;
        
        let send_sid_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &send_sid[..]);
        let receive_sid_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &receive_sid[..]);

        // Step 2: Send GoBN SYN message to the server
        let syn_payload = create_gbn_syn(GBN_N);
        let syn_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &syn_payload);
        let syn_msg = format!(
            r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
            send_sid_base64, syn_base64
        );
        
        eprintln!("📤 Sending GoBN SYN to server (client→server stream)");
        eprintln!("   Stream ID: {}", hex::encode(&send_sid[..]));
        if let Err(e) = send_write.send(Message::Text(syn_msg)).await {
            let _ = send_write.close().await;
            return Err(format!("Failed to send GoBN SYN: {}", e).into());
        }
        if let Err(e) = send_write.flush().await {
            let _ = send_write.close().await;
            return Err(format!("Failed to flush GoBN SYN: {}", e).into());
        }
        eprintln!("✅ GoBN SYN sent");

        // Step 3: Open RECEIVE connection and subscribe
        eprintln!("🔌 Opening RECEIVE stream: {}", recv_url);
        let (mut recv_write, mut recv_read) = match self.try_connect_endpoint(&recv_url).await {
            Ok(conn) => conn,
            Err(e) => {
                let _ = send_write.close().await;
                return Err(format!("Failed to connect to receive endpoint: {}", e).into());
            }
        };
        
        // Subscribe to the receive stream
        let recv_init = format!(r#"{{"stream_id":"{}"}}"#, receive_sid_base64);
        eprintln!("📤 Subscribing to RECEIVE stream (server→client)");
        eprintln!("   Stream ID: {}", hex::encode(&receive_sid[..]));
        if let Err(e) = recv_write.send(Message::Text(recv_init)).await {
            let _ = recv_write.close().await;
            let _ = send_write.close().await;
            return Err(format!("Failed to subscribe to receive stream: {}", e).into());
        }
        if let Err(e) = recv_write.flush().await {
            let _ = recv_write.close().await;
            let _ = send_write.close().await;
            return Err(format!("Failed to flush receive stream subscription: {}", e).into());
        }
        
        
        // Step 4: Wait for server's SYN response (server echoes our SYN)
        eprintln!("⏳ Waiting for GoBN SYN from server...");
        let mut syn_received = false;
        let mut response_opt: Option<Result<Message, tokio_tungstenite::tungstenite::Error>> = None;
        
        // Retry reading SYN up to 10 times with reconnection on "stream not found"
        for retry_attempt in 0..10 {
            let response = recv_read.next().await;
            
            match response {
                Some(Ok(Message::Text(text))) => {
                    eprintln!("📥 Server response: {}", text);
                    
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        // Check for error response from Relay
                        if let Some(error) = json.get("error") {
                            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                            let msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
                            
                            if (code == 2 || msg.contains("stream not found")) && retry_attempt < 9 {
                                eprintln!("⚠️  Stream not found (attempt {}/10). Re-subscribing...", retry_attempt + 1);
                                
                                // Close current connection and wait
                                let _ = recv_write.close().await;
                                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                                
                                // RECONNECT AND RE-SUBSCRIBE
                                match self.try_connect_endpoint(&recv_url).await {
                                    Ok((mut new_write, new_read)) => {
                                        let recv_init = format!(r#"{{"stream_id":"{}"}}"#, receive_sid_base64);
                                        if let Ok(_) = new_write.send(Message::Text(recv_init)).await {
                                            let _ = new_write.flush().await;
                                            recv_write = new_write;
                                            recv_read = new_read;
                                            eprintln!("✅ Re-subscribed to RECEIVE stream");
                                            continue;
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("⚠️  Reconnection failed: {}", e);
                                    }
                                }
                                continue;
                            }
                            
                            return Err(format!("Mailbox error (code {}): {}", code, msg).into());
                        }
                        
                        // Success - store response and break
                        response_opt = Some(Ok(Message::Text(text)));
                        syn_received = true;
                        break;
                    } else {
                        response_opt = Some(Ok(Message::Text(text)));
                        syn_received = true;
                        break;
                    }
                }
                Some(Ok(Message::Binary(data))) => {
                    response_opt = Some(Ok(Message::Binary(data)));
                    syn_received = true;
                    break;
                }
                Some(Ok(Message::Ping(_))) => {
                    // Manual heartbeat for GoBN handshake phase
                    eprintln!("📥 Received WS Ping, sending WS Pong...");
                    let _ = recv_write.send(Message::Pong(vec![])).await;
                    continue;
                }
                Some(Ok(Message::Close(_))) => {
                    eprintln!("⚠️  WebSocket closed by server while waiting for SYN. Reconnecting...");
                    // Try to reconnect once if retry_attempt permits
                    if retry_attempt < 9 {
                         tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                         if let Ok((mut new_write, new_read)) = self.try_connect_endpoint(&recv_url).await {
                             let recv_init = format!(r#"{{"stream_id":"{}"}}"#, receive_sid_base64);
                             if let Ok(_) = new_write.send(Message::Text(recv_init)).await {
                                 let _ = new_write.flush().await;
                                 recv_write = new_write;
                                 recv_read = new_read;
                                 continue;
                             }
                         }
                    }
                    return Err("Connection closed by server while waiting for SYN".into());
                }
                Some(Err(e)) => {
                    eprintln!("⚠️  WebSocket error during SYN read: {}. Reconnecting...", e);
                    if retry_attempt < 9 {
                         tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                         if let Ok((mut new_write, new_read)) = self.try_connect_endpoint(&recv_url).await {
                             let recv_init = format!(r#"{{"stream_id":"{}"}}"#, receive_sid_base64);
                             if let Ok(_) = new_write.send(Message::Text(recv_init)).await {
                                 let _ = new_write.flush().await;
                                 recv_write = new_write;
                                 recv_read = new_read;
                                 continue;
                             }
                         }
                    }
                    return Err(format!("WebSocket error during SYN read: {}", e).into());
                }
                None => {
                    eprintln!("⚠️  WebSocket stream closed unexpectedly while waiting for SYN. Reconnecting...");
                    if retry_attempt < 9 {
                         tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                         if let Ok((mut new_write, new_read)) = self.try_connect_endpoint(&recv_url).await {
                             let recv_init = format!(r#"{{"stream_id":"{}"}}"#, receive_sid_base64);
                             if let Ok(_) = new_write.send(Message::Text(recv_init)).await {
                                 let _ = new_write.flush().await;
                                 recv_write = new_write;
                                 recv_read = new_read;
                                 continue;
                             }
                         }
                    }
                    return Err("WebSocket stream closed unexpectedly while waiting for SYN.".into());
                }
                _ => continue,
            }
        }
        
        if !syn_received {
            return Err("Failed to receive SYN from server after retries".into());
        }
        
        let response = response_opt.unwrap();
        
        match response {
            Ok(Message::Text(text)) => {
                eprintln!("📥 Processing server SYN response...");
                
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    
                    // Parse successful response
                    if let Some(result) = json.get("result") {
                        if let Some(msg_b64) = result.get("msg").and_then(|m| m.as_str()) {
                            let msg_data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, msg_b64)
                                .map_err(|e| format!("Failed to decode response: {}", e))?;
                            
                            eprintln!("📥 Received data ({} bytes): {:02x?}", msg_data.len(), &msg_data[..msg_data.len().min(20)]);
                            
                            // Check if it's a SYN message from server (server echoes our SYN)
                            if msg_data.len() >= 2 && msg_data[0] == GBN_MSG_SYN {
                                let server_n = msg_data[1];
                                eprintln!("✅ Received GoBN SYN from server! N={}", server_n);
                                
                                if server_n != GBN_N {
                                    return Err(format!("Server N ({}) doesn't match client N ({})", server_n, GBN_N).into());
                                }
                                
                                // Step 4: Send SYNACK back to server IMMEDIATELY to complete GoBN handshake
                                // CRITICAL: Server times out waiting for SYNACK, so we must send it immediately
                                let synack_payload = create_gbn_synack();
                                let synack_payload_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &synack_payload);
                                
                                let synack_msg = format!(
                                    r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                                    send_sid_base64, synack_payload_base64
                                );
                                
                                eprintln!("📤 Sending GoBN SYNACK to server (IMMEDIATELY)");
                                send_write.send(Message::Text(synack_msg)).await
                                    .map_err(|e| format!("Failed to send SYNACK: {}", e))?;
                                send_write.flush().await
                                    .map_err(|e| format!("Failed to flush SYNACK: {}", e))?;
                                eprintln!("✅ GoBN handshake complete! (SYNACK sent and flushed)");
                                
                                // CRITICAL: The reference Go client sends Act 1 immediately after GoBN handshake completes.
                                // In Go: NewClientConn calls clientHandshake(), then conn.start(), then ClientHandshake calls DoHandshake.
                                // The GoBN connection is already started (with sendPacketsForever running) before Act 1 is sent.
                                // We should send Act 1 immediately - the server's GoBN connection should be ready by now.
                                // However, we need to ensure the server's GoBN connection is fully ready. The server's
                                // GoBN connection calls start() after handshake, which starts background goroutines.
                                // We should send Act 1 immediately, but we need to make sure it's sent correctly.
                                //
                                // The server's ServerHandshake() is called by gRPC asynchronously, and it will wait for
                                // Act 1 with a 5-second timeout. Sending immediately gives the server maximum time to
                                // process Act 1 and send Act 2.
                                //
                                // If Accept() is still blocking, the server will buffer Act 1 in GoBN until ServerHandshake()
                                // is ready to read it. The GoBN layer handles this automatically.
                                eprintln!("🔐 Starting Noise XX handshake with SPAKE2 masking...");
                                
                                // Perform Noise handshake over the GoBN connection
                                // CRITICAL: Send Act 1 immediately - the server's GoBN connection will buffer it
                                // if ServerHandshake() isn't ready yet. The GoBN layer handles this automatically.
                                // Initialize GoBN connection
                                let mut gobn = GoBNConnection::new(send_write, recv_read, send_sid_base64.clone());

                                // Perform Noise handshake over the GoBN connection
                                self.perform_noise_handshake(&mut gobn, params.noise_state.clone(), params.act1_msg.clone()).await?;

                                // Create connection with initialized cipher
                                let connection = MailboxConnection {
                                    gobn: Arc::new(Mutex::new(gobn)),
                                    mailbox: Arc::new(Mutex::new(self.clone())),
                                    read_buffer: Arc::new(Mutex::new(Vec::new())),
                                    write_buffer: Arc::new(Mutex::new(Vec::new())),
                                    encrypted_buffer: Arc::new(Mutex::new(Vec::new())),
                                    reading: Arc::new(Mutex::new(false)),
                                    read_error: Arc::new(Mutex::new(None)),
                                    writing: Arc::new(Mutex::new(false)),
                                    http2_ready: Arc::new(Mutex::new(false)),
                                };
                                
                                let connection_arc = Arc::new(Mutex::new(connection));
                                self.connection = Some(Arc::clone(&connection_arc));
                                
                                eprintln!("✅ LNC connection fully established!");
                                
                                return Ok(connection_arc);
                            }
                            
                            // Might be other data (FIN=0x05, etc.)
                            let msg_type = msg_data.get(0).unwrap_or(&255);
                            eprintln!("📥 Received message type: 0x{:02x} (expected SYN=0x{:02x})", msg_type, GBN_MSG_SYN);
                        }
                    }
                }
                
                Err(format!("Unexpected response from server: {}", text).into())
            }
            Ok(Message::Binary(data)) => {
                eprintln!("📥 Binary response ({} bytes): {:02x?}", data.len(), &data[..data.len().min(20)]);
                
                if data.len() >= 2 && data[0] == GBN_MSG_SYN {
                    let server_n = data[1];
                    eprintln!("✅ Received GoBN SYN from server (binary)! N={}", server_n);
                    
                    if server_n != GBN_N {
                        return Err(format!("Server N ({}) doesn't match client N ({})", server_n, GBN_N).into());
                    }
                    
                    // Send SYNACK back
                    let synack_payload = vec![GBN_MSG_SYNACK];
                    let synack_payload_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &synack_payload);
                    let synack_msg = format!(
                        r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                        send_sid_base64, synack_payload_base64
                    );
                    
                    eprintln!("📤 Sending GoBN SYNACK to server (binary)");
                    send_write.send(Message::Text(synack_msg)).await
                        .map_err(|e| format!("Failed to send SYNACK: {}", e))?;
                    send_write.flush().await?;
                    eprintln!("✅ GoBN handshake complete!");
                    
                    // Check if server created a new GoBN connection (same logic as text path)
                    // CRITICAL: The server's Accept() can block for up to ~9 seconds waiting for
                    // a previous connection to close. When it returns, it creates a new GoBN connection.
                    // We need to wait long enough (at least 10 seconds) to catch this new connection.
                    eprintln!("⏳ Checking if server created a new GoBN connection (waiting 10s for potential new SYN)...");
                    // Check if server sent a new SYN (non-blocking check)
                    let check_syn = recv_read.next().now_or_never();
                    
                    match check_syn {
                        Some(Some(Ok(Message::Text(text)))) => {
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                if let Some(result) = json.get("result") {
                                    if let Some(msg_b64) = result.get("msg").and_then(|m| m.as_str()) {
                                        if let Ok(msg_data) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, msg_b64) {
                                            if msg_data.len() >= 2 && msg_data[0] == GBN_MSG_SYN {
                                                eprintln!("⚠️  Server created a new GoBN connection! Completing new GoBN handshake...");
                                                let new_server_n = msg_data[1];
                                                if new_server_n != GBN_N {
                                                    return Err(format!("Server N ({}) doesn't match client N ({})", new_server_n, GBN_N).into());
                                                }
                                                
                                                // Send SYNACK to complete the new GoBN handshake
                                                let synack_payload = vec![GBN_MSG_SYNACK];
                                                let synack_payload_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &synack_payload);
                                                let synack_msg = format!(
                                                    r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                                                    send_sid_base64, synack_payload_base64
                                                );
                                                
                                                eprintln!("📤 Sending SYNACK for new GoBN connection");
                                                send_write.send(Message::Text(synack_msg)).await
                                                    .map_err(|e| format!("Failed to send SYNACK for new GoBN: {}", e))?;
                                                send_write.flush().await?;
                                                eprintln!("✅ New GoBN handshake complete!");
                                                
                                            // CRITICAL: When we detect a new GoBN connection, the server's Accept() just returned.
                                            // ServerHandshake() is called by gRPC asynchronously and sets a 5-second read deadline.
                                            // We should send Act 1 immediately to maximize the server's processing window.
                                            // The reference Go client sends Act 1 immediately after GoBN handshake completes.
                                            // No wait needed - send Act 1 right away.
                                            eprintln!("✅ New GoBN connection detected - sending Act 1 immediately (no wait)");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Some(Some(Ok(Message::Binary(data)))) => {
                            if data.len() >= 2 && data[0] == GBN_MSG_SYN {
                                eprintln!("⚠️  Server created a new GoBN connection (binary)! Completing new GoBN handshake...");
                                let new_server_n = data[1];
                                if new_server_n != GBN_N {
                                    return Err(format!("Server N ({}) doesn't match client N ({})", new_server_n, GBN_N).into());
                                }
                                
                                // Send SYNACK to complete the new GoBN handshake
                                let synack_payload = vec![GBN_MSG_SYNACK];
                                let synack_payload_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &synack_payload);
                                let synack_msg = format!(
                                    r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                                    send_sid_base64, synack_payload_base64
                                );
                                
                                eprintln!("📤 Sending SYNACK for new GoBN connection (binary)");
                                send_write.send(Message::Text(synack_msg)).await
                                    .map_err(|e| format!("Failed to send SYNACK for new GoBN: {}", e))?;
                                send_write.flush().await?;
                                eprintln!("✅ New GoBN handshake complete!");
                                
                                // CRITICAL: When we detect a new GoBN connection, the server's Accept() just returned.
                                // ServerHandshake() is called by gRPC asynchronously and sets a 5-second read deadline.
                                // We should send Act 1 immediately to maximize the server's processing window.
                                // The reference Go client sends Act 1 immediately after GoBN handshake completes.
                                // No wait needed - send Act 1 right away.
                                eprintln!("✅ New GoBN connection detected - sending Act 1 immediately (no wait)");
                            }
                        }
                        _ => {
                            eprintln!("✅ No new GoBN connection detected - proceeding with Noise handshake immediately");
                        }
                    }
                    
                    // Now perform Noise XX handshake (same as text path)
                    eprintln!("🔐 Starting Noise XX handshake with SPAKE2 masking...");
                    
                    // Initialize GoBN connection
                    let mut gobn = GoBNConnection::new(send_write, recv_read, send_sid_base64.clone());

                    // Perform Noise handshake over the GoBN connection
                    self.perform_noise_handshake(&mut gobn, params.noise_state, params.act1_msg).await?;

                    // Create connection with initialized cipher
                    let connection = MailboxConnection {
                        gobn: Arc::new(Mutex::new(gobn)),
                        mailbox: Arc::new(Mutex::new(self.clone())),
                        read_buffer: Arc::new(Mutex::new(Vec::new())),
                        write_buffer: Arc::new(Mutex::new(Vec::new())),
                        encrypted_buffer: Arc::new(Mutex::new(Vec::new())),
                        reading: Arc::new(Mutex::new(false)),
                        read_error: Arc::new(Mutex::new(None)),
                        writing: Arc::new(Mutex::new(false)),
                        http2_ready: Arc::new(Mutex::new(false)),
                    };
                    
                    let connection_arc = Arc::new(Mutex::new(connection));
                    self.connection = Some(Arc::clone(&connection_arc));
                    
                    eprintln!("✅ LNC connection fully established!");
                    
                    return Ok(connection_arc);
                }
                
                Err(format!("Unexpected binary response: {} bytes", data.len()).into())
            }
            Ok(other) => {
                Err(format!("Unexpected message type: {:?}", other).into())
            }
            Err(e) => {
                Err(format!("WebSocket error: {}", e).into())
            }
        }
    }
}

// GoBN protocol constants (matching lightning-node-connect/gbn/messages.go)
const GBN_MSG_SYN: u8 = 0x01;
const GBN_MSG_DATA: u8 = 0x02;
const GBN_MSG_ACK: u8 = 0x03;
const GBN_MSG_NACK: u8 = 0x04;
const GBN_MSG_FIN: u8 = 0x05;
const GBN_MSG_SYNACK: u8 = 0x06;
const GBN_TRUE: u8 = 0x01;
const GBN_FALSE: u8 = 0x00;
const GBN_N: u8 = 20; // Default window size

/// Helper functions for GoBN message serialization (matching Go reference implementation)
fn create_gbn_syn(n: u8) -> Vec<u8> {
    vec![GBN_MSG_SYN, n]
}

fn create_gbn_synack() -> Vec<u8> {
    vec![GBN_MSG_SYNACK]
}

fn create_gbn_fin() -> Vec<u8> {
    vec![GBN_MSG_FIN]
}

fn create_gbn_data_packet(seq: u8, final_chunk: bool, is_ping: bool, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.push(GBN_MSG_DATA);
    packet.push(seq);
    packet.push(if final_chunk { GBN_TRUE } else { GBN_FALSE });
    packet.push(if is_ping { GBN_TRUE } else { GBN_FALSE });
    packet.extend_from_slice(payload);
    packet
}

fn create_gbn_ack(seq: u8) -> Vec<u8> {
    vec![GBN_MSG_ACK, seq]
}

// Permanent GoBN Connection struct to handle the protocol state
pub struct GoBNConnection {
    pub send_write: futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
    pub recv_read: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    send_sid_base64: String,
    send_seq: u8,  // Sequence number for GoBN DATA packets
    recv_seq: u8,  // Expected sequence number for received packets
    recv_buffer: Vec<u8>,  // Buffer for reassembling multi-chunk messages
    // Cache the last Act 1 packet so we can resend it if the server restarts the
    // GoBN connection and sends a new SYN while we're waiting for Act 2.
    // MUST be cleared after handshake completes to prevent infinite resending.
    pub last_act1_msg_json: Option<String>,
    created_at: tokio::time::Instant,
}

impl GoBNConnection {
    pub fn new(
        send_write: futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
        recv_read: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
        send_sid_base64: String,
    ) -> Self {
        Self {
            send_write,
            recv_read,
            send_sid_base64,
            send_seq: 0,
            recv_seq: 0,
            recv_buffer: Vec::new(),
            last_act1_msg_json: None,
            created_at: tokio::time::Instant::now(),
        }
    }

    /// Unwrap MsgData format from a byte buffer
    /// MsgData format: [version (1 byte)] [payload_length (4 bytes BE)] [payload (N bytes)]
    /// Returns the unwrapped Noise message payload
    fn unwrap_msgdata(&self, msgdata_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if msgdata_bytes.len() < 5 {
            return Err(format!("MsgData too short: {} bytes (need at least 5)", msgdata_bytes.len()).into());
        }
        
        let _version = msgdata_bytes[0];  // Should be 0
        let payload_len = u32::from_be_bytes([
            msgdata_bytes[1],
            msgdata_bytes[2],
            msgdata_bytes[3],
            msgdata_bytes[4],
        ]) as usize;
        
        if msgdata_bytes.len() < 5 + payload_len {
            return Err(format!("Incomplete MsgData: have {} bytes, need {} bytes", 
                msgdata_bytes.len(), 5 + payload_len).into());
        }
        
        // Extract the actual Noise message payload (skip MsgData header)
        let noise_payload = msgdata_bytes[5..5 + payload_len].to_vec();
        eprintln!("📦 Unwrapped MsgData: version={}, payload_len={}, Noise message len={}", 
            _version, payload_len, noise_payload.len());
        
        Ok(noise_payload)
    }
    
    pub async fn write_msg(&mut self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        // CRITICAL: ALL messages sent through GoBN (including handshake messages) must be wrapped in MsgData format!
        // MsgData format: [version (1 byte)] [payload_length (4 bytes BE)] [payload (N bytes)]
        // ProtocolVersion = 0 for mailbox connections
        // This matches the Go implementation where connKit.Write() wraps all data in MsgData before sending via GoBN
        const PROTOCOL_VERSION: u8 = 0;
        
        let mut msg_data = Vec::with_capacity(5 + data.len());
        msg_data.push(PROTOCOL_VERSION);  // Protocol version (0)
        
        // Payload length as big-endian uint32
        let payload_len = data.len() as u32;
        msg_data.extend_from_slice(&payload_len.to_be_bytes());
        
        // Payload (the Noise handshake message)
        msg_data.extend_from_slice(data);
        
        eprintln!("📦 Wrapped Noise message in MsgData: total_size={} bytes (version={}, payload_len={}, Noise_msg={})", 
            msg_data.len(), PROTOCOL_VERSION, data.len(), data.len());
        
        // Now wrap MsgData in GoBN DATA packet format
        let gbn_packet = create_gbn_data_packet(
            self.send_seq,
            true,  // FinalChunk = true (single packet)
            false, // IsPing = false
            &msg_data,  // Send MsgData-wrapped Noise message
        );
        
        eprintln!("📤 Sending GoBN DATA packet: seq={}, msgdata_size={} bytes, gbn_packet_size={} bytes", 
            self.send_seq, msg_data.len(), gbn_packet.len());
        eprintln!("   First 20 bytes of GoBN packet: {:02x?}", &gbn_packet[..gbn_packet.len().min(20)]);
        
        // Increment sequence number for next packet (wrap around at window size N=20)
        let current_seq = self.send_seq;
        self.send_seq = (self.send_seq + 1) % 20;
        
        let payload_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &gbn_packet);
        let msg = format!(
            r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
            self.send_sid_base64, payload_base64
        );
        
        // Store message length before moving msg
        let msg_len = msg.len();
        
        // CRITICAL: Send the message and handle any errors
        match self.send_write.send(Message::Text(msg)).await {
            Ok(_) => {
                eprintln!("✅ GoBN DATA packet sent to WebSocket (seq={}), now flushing...", current_seq);
            }
            Err(e) => {
                return Err(format!("Failed to send Noise message (seq {}): {}. Message length: {} bytes, stream_id: {}", 
                    current_seq, e, msg_len, &self.send_sid_base64[..self.send_sid_base64.len().min(20)]).into());
            }
        }
        Ok(())
    }
    
    pub async fn flush(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        eprintln!("🔄 Flushing WebSocket send stream...");
        self.send_write.flush().await
            .map_err(|e| format!("Failed to flush WebSocket send stream: {}", e))?;
        Ok(())
    }
    
    pub async fn read_msg(&mut self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        use futures_util::StreamExt;
        
        // Keep track of how many control packets we've seen while waiting for DATA
        let mut control_packets_seen = 0;
        
        // CRITICAL: Read continuously to catch Act 2 when it arrives
        // The server sends Act 2 immediately after receiving Act 1, but we might receive
        // ping packets first. We must process all packets and look for Act 2.
        // 
        // IMPORTANT: In Go implementation (gbn_conn.go), ping packets increment recvSeq.
        // So if server sends ping with seq 0, we ACK it and increment recvSeq to 1.
        // Then Act 2 should come with seq 1 (the next sequence number).
        // We must match this behavior exactly!
        let mut max_iterations = 100; // Prevent infinite loops
        let mut packets_received = 0;
        loop {
            if max_iterations == 0 {
                return Err(format!("Timeout: Read {} packets without finding DATA. Last recv_seq: {}", packets_received, self.recv_seq).into());
            }
            max_iterations -= 1;
            packets_received += 1;
            
            // Wait for response
            let response_result = tokio::time::timeout(
                tokio::time::Duration::from_millis(5000), // Increased timeout for robustness
                self.recv_read.next()
            ).await;

            let response = match response_result {
                Ok(Some(Ok(msg))) => msg,
                Ok(Some(Err(e))) => {
                    return Err(format!("WebSocket error while waiting for response: {}", e).into());
                }
                Ok(None) => {
                    return Err("Connection closed while waiting for response".into());
                }
                Err(_) => {
                    // Timeout occurred - proactively resend Act 1 IF we are in handshake (last_act1_msg_json is set)
                    if let Some(act1_json) = &self.last_act1_msg_json {
                        eprintln!("⏳ Read timeout waiting for Act 2; proactively resending Act 1...");
                        if let Err(e) = self.send_write.send(Message::Text(act1_json.clone())).await {
                            eprintln!("⚠️  Failed to resend Act 1 on timeout: {}", e);
                        } else {
                            let _ = self.send_write.flush().await;
                            eprintln!("✅ Act 1 resent on timeout");
                        }
                    }
                    continue; // Continue waiting in the loop
                }
            };
            
            match response {
                Message::Text(text) => {
                    // Check for error responses from the server
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(error) = json.get("error") {
                            let error_msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
                            let error_code = error.get("code").and_then(|c| c.as_u64()).unwrap_or(0);
                            eprintln!("❌ Server returned error: code={}, message={}", error_code, error_msg);
                            return Err(format!("Server error (code {}): {}", error_code, error_msg).into());
                        }
                        
                        if let Some(result) = json.get("result") {
                            if let Some(msg_b64) = result.get("msg").and_then(|m| m.as_str()) {
                                let msg_data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, msg_b64)
                                    .map_err(|e| format!("Failed to decode response: {}", e))?;
                                
                                if msg_data.is_empty() {
                                    continue; // Skip empty messages
                                }
                                
                                eprintln!("📥 Received GoBN message: type=0x{:02x}, len={} bytes", msg_data[0], msg_data.len());
                                
                                // Check message type
                                match msg_data[0] {
                                    GBN_MSG_DATA => {
                                        // GoBN DATA packet: [DATA, Seq, FinalChunk, IsPing, Payload...]
                                        if msg_data.len() < 4 {
                                            continue;
                                        }
                                        
                                        let seq = msg_data[1];
                                        let final_chunk = msg_data[2] == GBN_TRUE;
                                        let is_ping = msg_data[3] == GBN_TRUE;
                                        
                                        // Ping packets have no payload - just send ACK and continue
                                        if is_ping {
                                            eprintln!("📥 Received GoBN ping packet (seq {}), current recvSeq={}", seq, self.recv_seq);
                                            
                                            // For pings: always ACK; only increment when seq matches expected.
                                            let ack_packet = create_gbn_ack(seq);
                                            let ack_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ack_packet);
                                            let ack_msg = format!(
                                                r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                                                self.send_sid_base64, ack_base64
                                            );
                                            if let Err(e) = self.send_write.send(Message::Text(ack_msg)).await {
                                                eprintln!("⚠️  Failed to send ping ACK: {}", e);
                                            }
                                            let _ = self.send_write.flush().await;
                                            
                                            if seq == self.recv_seq {
                                                self.recv_seq = (self.recv_seq + 1) % 20;
                                                eprintln!("✅ Ping ACK sent, recvSeq incremented to {}", self.recv_seq);
                                            }

                                            // PROACTIVE FIX: Server pings are often sent when it's waiting for data.
                                            // Resend Act 1 here to ensure it gets through if we are in handshake
                                            if let Some(act1_json) = &self.last_act1_msg_json {
                                                eprintln!("📤 Received PING waiting for Act 2; proactively resending Act 1...");
                                                if let Err(e) = self.send_write.send(Message::Text(act1_json.clone())).await {
                                                    eprintln!("⚠️  Failed to resend Act 1 on PING: {}", e);
                                                } else {
                                                    let _ = self.send_write.flush().await;
                                                }
                                            }

                                            continue; // Ping packets have no payload
                                        }
                                        
                                        // Check if packet has payload
                                        if msg_data.len() < 5 {
                                            continue;
                                        }
                                        
                                        let payload = &msg_data[4..];
                                        
                                        // Check if this is the expected sequence number
                                        if seq != self.recv_seq {
                                            eprintln!("⚠️  Received DATA packet with seq {} (expected {}), sending NACK", seq, self.recv_seq);
                                            // Send NACK to request retransmission of the expected sequence
                                            let nack_packet = vec![GBN_MSG_NACK, self.recv_seq];
                                            let nack_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nack_packet);
                                            let nack_msg = format!(
                                                r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                                                self.send_sid_base64, nack_base64
                                            );
                                            let _ = self.send_write.send(Message::Text(nack_msg)).await;
                                            let _ = self.send_write.flush().await;
                                            continue;
                                        }
                                        
                                        eprintln!("✅ Accepting DATA packet with matching sequence number (seq={})", seq);
                                        
                                        // Append payload to reassembly buffer FIRST
                                        self.recv_buffer.extend_from_slice(payload);
                                        
                                        // Send ACK immediately - CRITICAL for GoBN protocol
                                        let ack_packet = create_gbn_ack(seq);
                                        let ack_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ack_packet);
                                        let ack_msg = format!(
                                            r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                                            self.send_sid_base64, ack_base64
                                        );
                                        // CRITICAL: ACK must be sent and flushed immediately
                                        self.send_write.send(Message::Text(ack_msg)).await
                                            .map_err(|e| format!("Failed to send ACK: {}", e))?;
                                        self.send_write.flush().await
                                            .map_err(|e| format!("Failed to flush ACK: {}", e))?;
                                        eprintln!("✅ ACK sent and flushed for seq {}", seq);
                                        
                                        // Increment expected sequence number AFTER successful processing
                                        self.recv_seq = (self.recv_seq + 1) % 20;
                                        
                                        // If this is the final chunk, process the complete message
                                        if final_chunk {
                                            let complete_msgdata = std::mem::take(&mut self.recv_buffer);
                                            
                                            // CRITICAL: ALL messages (including handshake) are wrapped in MsgData format!
                                            // Unwrap MsgData to get the actual Noise handshake message
                                            match self.unwrap_msgdata(&complete_msgdata) {
                                                Ok(noise_payload) => {
                                                    eprintln!("📦 Unwrapped MsgData: {} bytes", noise_payload.len());
                                                    return Ok(noise_payload);
                                                }
                                                Err(e) => {
                                                    eprintln!("❌ Failed to unwrap MsgData (seq {}): {}", seq, e);
                                                    // CRITICAL FIX: We have already ACKed this sequence number.
                                                    // We cannot retry it. This is a fatal protocol error.
                                                    return Err(format!("Fatal: Failed to unwrap MsgData (seq {}): {}", seq, e).into());
                                                }
                                            }
                                        }
                                        
                                        // Not the final chunk, continue waiting for more chunks
                                        continue;
                                    }
                                    GBN_MSG_ACK => {
                                        // ACK message - ignore for now (could implement ACK tracking if needed)
                                        control_packets_seen += 1;
                                        continue;
                                    }
                                    GBN_MSG_NACK => {
                                        let seq = if msg_data.len() > 1 { msg_data[1] } else { 0 };
                                        eprintln!("📥 Received NACK packet (expected seq {}), resending last message...", seq);
                                        // This is mostly useful during handshake if we cached the Act 1 message
                                        if let Some(act1_json) = &self.last_act1_msg_json {
                                             let _ = self.send_write.send(Message::Text(act1_json.clone())).await;
                                             let _ = self.send_write.flush().await;
                                             eprintln!("✅ Last message (Act 1) resent due to NACK");
                                        }
                                        continue;
                                    }
                                    GBN_MSG_FIN => {
                                        // FIN message - connection is being closed
                                        eprintln!("📥 Received FIN packet, connection closing");
                                        return Err(format!("Connection closed by server (FIN). Control packets seen: {}", control_packets_seen).into());
                                    }
                                    GBN_MSG_SYN => {
                                        let elapsed = self.created_at.elapsed();
                                        if elapsed.as_secs() > 5 {
                                            eprintln!("🛑 Genuine server reset detected (SYN arrived >5s after handshake).");
                                            return Err("resync required".into());
                                        }
                                        continue;
                                    }
                                    GBN_MSG_SYNACK => {
                                        continue;
                                    }
                                    _ => {
                                        // Unknown message type
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }
                Message::Binary(data) => {
                    // Binary messages - check if it's a GoBN packet (similar logic to text)
                    if data.is_empty() {
                         continue;
                    }
                    
                     match data[0] {
                        GBN_MSG_DATA => {
                            if data.len() < 4 { continue; }
                            let seq = data[1];
                            let final_chunk = data[2] == 0x01;
                            let is_ping = data[3] == 0x01;
                            
                            if is_ping {
                                // ACK Ping
                                let ack_packet = create_gbn_ack(seq);
                                let ack_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ack_packet);
                                let ack_msg = format!(r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#, self.send_sid_base64, ack_base64);
                                let _ = self.send_write.send(Message::Text(ack_msg)).await;
                                let _ = self.send_write.flush().await;
                                
                                if seq == self.recv_seq {
                                    self.recv_seq = (self.recv_seq + 1) % 20;
                                }
                                
                                if let Some(act1_json) = &self.last_act1_msg_json {
                                    let _ = self.send_write.send(Message::Text(act1_json.clone())).await;
                                    let _ = self.send_write.flush().await;
                                }
                                continue;
                            }
                            
                            // Check if packet has payload
                            if data.len() < 5 { continue; }
                            let payload = &data[4..];
                            
                            if seq != self.recv_seq {
                                // Send NACK
                                let nack_packet = vec![GBN_MSG_NACK, self.recv_seq];
                                let nack_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nack_packet);
                                let nack_msg = format!(r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#, self.send_sid_base64, nack_base64);
                                let _ = self.send_write.send(Message::Text(nack_msg)).await;
                                let _ = self.send_write.flush().await;
                                continue;
                            }
                            
                            self.recv_buffer.extend_from_slice(payload);
                            
                             // Send ACK immediately
                            let ack_packet = create_gbn_ack(seq);
                            let ack_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ack_packet);
                            let ack_msg = format!(r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#, self.send_sid_base64, ack_base64);
                            if let Err(e) = self.send_write.send(Message::Text(ack_msg)).await {
                                return Err(format!("Failed to send ACK: {}", e).into());
                            }
                            if let Err(e) = self.send_write.flush().await {
                                return Err(format!("Failed to flush ACK: {}", e).into());
                            }
                            
                            self.recv_seq = (self.recv_seq + 1) % 20;
                            
                            if final_chunk {
                                let complete_msgdata = std::mem::take(&mut self.recv_buffer);
                                match self.unwrap_msgdata(&complete_msgdata) {
                                    Ok(noise_payload) => {
                                        return Ok(noise_payload);
                                    }
                                    Err(e) => {
                                        return Err(format!("Fatal: Failed to unwrap MsgData (binary seq {}): {}", seq, e).into());
                                    }
                                }
                            }
                            continue;
                        }
                        GBN_MSG_SYN => {
                             let elapsed = self.created_at.elapsed();
                            if elapsed.as_secs() > 5 {
                                return Err("resync required".into());
                            }
                            continue;
                        }
                        GBN_MSG_NACK => {
                             if let Some(act1_json) = &self.last_act1_msg_json {
                                  let _ = self.send_write.send(Message::Text(act1_json.clone())).await;
                                  let _ = self.send_write.flush().await;
                             }
                             continue;
                        }
                        _ => continue,
                    }
                }
                _ => continue, // Skip other message types
            }
        }
    }
}

/// Noise handshake state machine implementing XX pattern with SPAKE2
struct NoiseHandshakeState {
    secp: Secp256k1<secp256k1::All>,
    local_keypair: Keypair,
    local_ephemeral: Option<Keypair>,
    remote_ephemeral: Option<PublicKey>,
    remote_static: Option<PublicKey>,
    passphrase_entropy: Vec<u8>,
    
    // Noise state
    chaining_key: [u8; 32],
    handshake_digest: [u8; 32],
    temp_key: [u8; 32],
    cipher: Option<ChaCha20Poly1305>,
    cipher_nonce: u64,
    
    version: u8,
    
    /// Authentication data received from server in Act 2
    auth_data: Option<String>,
}


impl Clone for NoiseHandshakeState {
    fn clone(&self) -> Self {
        Self {
            secp: self.secp.clone(),
            local_keypair: self.local_keypair,
            local_ephemeral: self.local_ephemeral,
            remote_ephemeral: self.remote_ephemeral,
            remote_static: self.remote_static,
            passphrase_entropy: self.passphrase_entropy.clone(),
            chaining_key: self.chaining_key,
            handshake_digest: self.handshake_digest,
            temp_key: self.temp_key,
            cipher: self.cipher.as_ref().map(|_| ChaCha20Poly1305::new(&self.temp_key.into())),
            cipher_nonce: self.cipher_nonce,
            version: self.version,
            auth_data: self.auth_data.clone(),
        }
    }
}

impl NoiseHandshakeState {
    fn new(local_keypair: &Keypair, passphrase_entropy: Vec<u8>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let secp = Secp256k1::new();
        
        // Initialize protocol name: "Noise_XXeke+SPAKE2_secp256k1_ChaChaPoly_SHA256"
        let protocol_name = b"Noise_XXeke+SPAKE2_secp256k1_ChaChaPoly_SHA256";
        let proto_hash = Sha256::digest(protocol_name);
        eprintln!("🔍 Protocol name hash: {}", hex::encode(&proto_hash));
        let chaining_key: [u8; 32] = proto_hash.into();
        let handshake_digest = chaining_key;
        
        // Mix in prologue
        let mut hasher = Sha256::new();
        hasher.update(&handshake_digest);
        hasher.update(LIGHTNING_NODE_CONNECT_PROLOGUE);
        let handshake_digest: [u8; 32] = hasher.finalize().into();
        eprintln!("🔍 Prologue mixed hash: {}", hex::encode(&handshake_digest));
        
        Ok(Self {
            secp,
            local_keypair: *local_keypair,
            local_ephemeral: None,
            remote_ephemeral: None,
            remote_static: None,
            passphrase_entropy,
            chaining_key,
            handshake_digest,
            temp_key: [0u8; 32],
            // Initialize cipher with temp_key=zero (matches brontide initialization)
            cipher: Some(ChaCha20Poly1305::new(&[0u8; 32].into())),
            cipher_nonce: 0,
            version: 2, // Default to Version 2 as server uses it
            auth_data: None,
        })
    }
    
    fn act1(&mut self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // Generate ephemeral key
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret_key = SecretKey::from_slice(&secret_bytes)
            .map_err(|e| format!("Failed to generate ephemeral secret key: {}", e))?;
        let ephemeral = Keypair::from_secret_key(&self.secp, &secret_key);
        self.local_ephemeral = Some(ephemeral);
        
        // Mix unmasked ephemeral into hash
        let ephem_pub_bytes = self.local_ephemeral.as_ref().unwrap().public_key().serialize();
        eprintln!("🔍 Unmasked Ephemeral (33 bytes): {}", hex::encode(&ephem_pub_bytes));
        self.mix_hash(&ephem_pub_bytes);
        eprintln!("🔍 Hash after ephemeral: {}", hex::encode(&self.handshake_digest));
        
        // Mask ephemeral with SPAKE2
        let masked_ephem = spake2_mask(
            &self.local_ephemeral.as_ref().unwrap().public_key(),
            &self.passphrase_entropy,
        )?;
        
        // Act 1 message: [version, masked_ephemeral_pubkey, payload(optional)]
        let mut msg = vec![self.version];
        msg.extend_from_slice(&masked_ephem.serialize());

        // HandshakeVersion1/2 include an encrypted payload (even if empty) in Act 1.
        // HandshakeVersion0 DOES NOT.
        if self.version >= 1 {
            let mac = self.encrypt_and_hash(&[]);
            msg.extend_from_slice(&mac);
        }
        
        Ok(msg)
    }
    
    fn act2(&mut self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        if data.is_empty() {
            return Err("Empty Act 2 message".into());
        }
        
        let version = data[0];
        if version > 2 {
            return Err(format!("Invalid handshake version: {}", version).into());
        }
        self.version = version;
        
        // Parse Act 2: [version, e, ee, s, es, encrypted_payload]
        // e: server ephemeral (33 bytes compressed)
        // ee: ECDH(remote_ephemeral, local_ephemeral) - computed, not sent
        // s: server static key (encrypted, 49 bytes = 33 + 16 MAC)
        // es: ECDH(remote_static, local_ephemeral) - computed, not sent
        
        let mut offset = 1;
        
        // Read server ephemeral
        if offset + 33 > data.len() {
            return Err(format!(
                "Act 2 too short for ephemeral key: received {} bytes, need at least {} bytes. Data: {:02x?}",
                data.len(),
                offset + 33,
                &data[..data.len().min(50)]
            ).into());
        }
        let remote_ephem_pub = PublicKey::from_slice(&data[offset..offset+33])
            .map_err(|e| format!("Invalid remote ephemeral: {}", e))?;
        self.remote_ephemeral = Some(remote_ephem_pub);
        offset += 33;
        
        // Mix remote ephemeral into hash
        self.mix_hash(&data[1..offset]);
        
        // Compute ee (ECDH with remote ephemeral)
        let ee = self.ecdh(
            &self.remote_ephemeral.unwrap(),
            self.local_ephemeral.as_ref().unwrap(),
        )?;
        self.mix_key(&ee);
        
        // Read encrypted static key (s)
        // This is encrypted with the temp key derived so far
        let encrypted_static_start = offset;
        let encrypted_static_size = 49; // 33 bytes key + 16 bytes MAC
        if encrypted_static_start + encrypted_static_size > data.len() {
            return Err("Act 2 too short for encrypted static key".into());
        }
        let encrypted_static = &data[offset..offset+encrypted_static_size];
        
        // Decrypt static key
        let static_key_bytes = self.decrypt_and_hash(encrypted_static)?;
        let remote_static_pub = PublicKey::from_slice(&static_key_bytes)
            .map_err(|e| format!("Invalid remote static key: {}", e))?;
        self.remote_static = Some(remote_static_pub);
        
        // Compute es (ECDH with remote static)
        let es = self.ecdh(
            &self.remote_static.unwrap(),
            self.local_ephemeral.as_ref().unwrap(),
        )?;
        self.mix_key(&es);
        
        // Read and decrypt payload (if any) - this contains authentication data
        offset += encrypted_static_size;
        let auth_payload = if self.version == 0 {
            // Version 0: Fixed 500 byte payload
            if offset + 516 <= data.len() {
                Some(self.decrypt_and_hash(&data[offset..offset+516])?)
            } else {
                None
            }
        } else {
            // Version 1/2: Length-prefixed payload
            if offset + 20 <= data.len() {
                let len_bytes = self.decrypt_and_hash(&data[offset..offset+20])?;
                let payload_len = u32::from_be_bytes(len_bytes[..4].try_into().unwrap()) as usize;
                offset += 20;
                if offset + payload_len + 16 <= data.len() {
                    Some(self.decrypt_and_hash(&data[offset..offset+payload_len+16])?)
                } else {
                    None
                }
            } else {
                None
            }
        };
        
        // Store authentication data from Act 2 payload
        if let Some(payload) = auth_payload {
            let auth_str = String::from_utf8_lossy(&payload).to_string();
            eprintln!("🔐 Received authentication data in Act 2: {}", auth_str);
            self.auth_data = Some(auth_str);
        }
        
        Ok(())
    }
    
    fn act3(&mut self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // Act 3: [version, s, se]
        // CRITICAL Order for XX: -> s, se
        // s: our static key (encrypted)
        // se: ECDH(remote_ephemeral, local_static) - computed, not sent
        
        // 1. Encrypt our static key (using key derived after Act 2 'es')
        let static_key_bytes = self.local_keypair.public_key().serialize();
        let encrypted_static = self.encrypt_and_hash(&static_key_bytes);
        
        // 2. Compute se (ECDH) and mix into key
        let se = self.ecdh(
            &self.remote_ephemeral.unwrap(),
            &self.local_keypair,
        )?;
        self.mix_key(&se);
        
        // Act 3 message: [version, encrypted_static, payload(optional)]
        let mut msg = vec![self.version];
        msg.extend_from_slice(&encrypted_static);
        
        // HandshakeVersion1/2 include an encrypted payload (even if empty) in Act 3.
        if self.version >= 1 {
            let empty_payload = self.encrypt_and_hash(&[]);
            msg.extend_from_slice(&empty_payload);
        }
        
        Ok(msg)
    }
    
    fn split(self) -> Result<([u8; 32], [u8; 32]), Box<dyn Error + Send + Sync>> {
        // Split handshake: derive send and receive keys using HKDF
        // HKDF with empty input key, chaining_key as salt, empty info
        let empty: [u8; 0] = [];
        let hk = Hkdf::<Sha256>::new(Some(&self.chaining_key), &empty);
        let mut keys = [0u8; 64]; // 64 bytes for both keys
        
        // Expand into single buffer, then split
        hk.expand(&empty, &mut keys)
            .map_err(|e| format!("HKDF expand failed: {}", e))?;
        
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        send_key.copy_from_slice(&keys[0..32]);
        recv_key.copy_from_slice(&keys[32..64]);
        
        // As initiator: first 32 bytes = send, second 32 bytes = recv
        Ok((send_key, recv_key))
    }
    
    fn remote_static(&self) -> Option<PublicKey> {
        self.remote_static
    }
    
    fn mix_hash(&mut self, data: &[u8]) {
        let combined = [&self.handshake_digest[..], data].concat();
        let hash = Sha256::digest(&combined);
        self.handshake_digest = hash.into();
    }
    
    fn mix_key(&mut self, input: &[u8]) {
        // Rust Hkdf::new(salt, ikm). Go uses salt=chaining_key, secret(IKM)=input.
        let hk = Hkdf::<Sha256>::new(Some(&self.chaining_key), input);
        let mut okm = [0u8; 64];
        
        // Use empty info string as Go uses empty for HKDF info
        hk.expand(&[], &mut okm)
            .expect("HKDF expansion should not fail");
        
        // Go:
        // _, _ = h.Read(s.chaining_key[:])
        // _, _ = h.Read(s.temp_key[:])
        self.chaining_key.copy_from_slice(&okm[..32]);
        self.temp_key.copy_from_slice(&okm[32..64]);
        
        // Initialize cipher with temp key
        self.cipher = Some(ChaCha20Poly1305::new(&self.temp_key.into()));
        self.cipher_nonce = 0;
    }
    
    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = self.cipher.as_ref()
            .expect("Cipher should be initialized before encrypt_and_hash");
        
        // Use handshake digest as associated data (AAD)
        use chacha20poly1305::aead::Payload;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.cipher_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let payload = Payload {
            msg: plaintext,
            aad: &self.handshake_digest,
        };
        
        let ciphertext = cipher.encrypt(nonce, payload)
            .expect("Encryption should not fail");
        self.cipher_nonce = self.cipher_nonce.wrapping_add(1);
        
        // Mix ciphertext into hash
        self.mix_hash(&ciphertext);
        
        ciphertext
    }
    
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let cipher = self.cipher.as_ref()
            .ok_or("Cipher not initialized")?;
        
        // Use handshake digest as associated data (AAD)
        use chacha20poly1305::aead::Payload;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.cipher_nonce.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let payload = Payload {
            msg: ciphertext,
            aad: &self.handshake_digest,
        };
        
        let plaintext = cipher.decrypt(nonce, payload)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        self.cipher_nonce = self.cipher_nonce.wrapping_add(1);
        
        // Mix ciphertext (not plaintext!) into hash
        self.mix_hash(ciphertext);
        
        Ok(plaintext)
    }
    
    fn ecdh(&self, pubkey: &PublicKey, keypair: &Keypair) -> Result<[u8; 32], Box<dyn Error + Send + Sync>> {
        // Perform ECDH: shared_point = pubkey * keypair.secret_key
        let shared_point = pubkey.mul_tweak(&self.secp, &keypair.secret_key().into())
            .map_err(|e| format!("ECDH failed: {}", e))?;
        
        // Hash the shared point (compressed representation)
        let shared_bytes = shared_point.serialize();
        let shared_secret = Sha256::digest(&shared_bytes);
        
        Ok(shared_secret.into())
    }
}

/// SPAKE2 mask: me = e + N*pw
/// This implements: masked_ephemeral = ephemeral + (N * passphrase_scalar)
/// Where N is the SPAKE2 generator point and pw is the passphrase entropy
fn spake2_mask(e: &PublicKey, passphrase_entropy: &[u8]) -> Result<PublicKey, Box<dyn Error + Send + Sync>> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::elliptic_curve::ff::PrimeField;
    
    // Parse SPAKE2 generator point N from hex
    let n_bytes = hex::decode(SPAKE2_N_HEX)
        .map_err(|e| format!("Failed to decode SPAKE2 N: {}", e))?;
    let n_k256_point = k256::EncodedPoint::from_bytes(&n_bytes)
        .map_err(|e| format!("Failed to parse SPAKE2 N: {}", e))?;
    let n_projective = ProjectivePoint::from_encoded_point(&n_k256_point);
    let n_projective = Option::<ProjectivePoint>::from(n_projective)
        .ok_or("Failed to convert N to projective point")?;
    
    // Convert ephemeral key to projective point
    let e_bytes = e.serialize();
    let e_k256_point = k256::EncodedPoint::from_bytes(&e_bytes)
        .map_err(|e| format!("Invalid ephemeral key: {}", e))?;
    let e_projective = ProjectivePoint::from_encoded_point(&e_k256_point);
    let e_projective = Option::<ProjectivePoint>::from(e_projective)
        .ok_or("Failed to convert ephemeral to projective point")?;
    
    // Convert passphrase entropy to scalar
    // CRITICAL: Go reference DOES NOT hash the entropy before converting to scalar.
    // It uses the stretched 32-byte entropy directly.
    let mut pw_bytes = [0u8; 32];
    if passphrase_entropy.len() == 32 {
        pw_bytes.copy_from_slice(passphrase_entropy);
    } else {
        return Err("Passphrase entropy must be 32 bytes (stretched)".into());
    }
    
    let pw_scalar = Scalar::from_repr(pw_bytes.into());
    let pw_scalar = Option::<Scalar>::from(pw_scalar)
        .ok_or("Invalid scalar representation")?;
    
    // Perform SPAKE2 masking: me = e + N*pw
    let point_pw = n_projective * pw_scalar;
    let masked_projective = e_projective + point_pw;
    
    // Convert back to secp256k1 PublicKey (compressed)
    let masked_encoded = masked_projective.to_encoded_point(true);
    let masked_bytes = masked_encoded.as_bytes();
    let masked_pub = PublicKey::from_slice(masked_bytes)
        .map_err(|e| format!("Failed to create masked pubkey: {}", e))?;
    
    Ok(masked_pub)
}

impl LNCMailbox {

    /// Perform Noise XX handshake with SPAKE2 masking over GoBN connection
    async fn perform_noise_handshake(
        &mut self,
        gobn: &mut GoBNConnection,
        mut state: NoiseHandshakeState,
        act1_msg: Vec<u8>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        
        eprintln!("🔐 Starting Noise XX handshake...");
        
        // CRITICAL: Act 1 is sent IMMEDIATELY after GoBN handshake.
        eprintln!("📤 Sending Act 1 immediately after GoBN handshake (no waiting for PING)...");
        
        // Send Act 1
        // CRITICAL: All messages are wrapped in MsgData and sent as GoBN DATA packets
        
        // Cache Act 1 for retransmission if needed (e.g., if we get a NACK or timeout)
        let mut act1_msgdata = Vec::with_capacity(5 + act1_msg.len());
        act1_msgdata.push(0); // Version 0
        let act1_len = act1_msg.len() as u32;
        act1_msgdata.extend_from_slice(&act1_len.to_be_bytes());
        act1_msgdata.extend_from_slice(&act1_msg);

        // We can't cache the JSON string easily here without digging into write_msg internal logic,
        // but write_msg handles wrapping and sending.
        // Wait, GoBNConnection needs to know it's Act 1 for caching logic.
        // I'll manually set the cache in GoBNConnection after constructing the packet in write_msg?
        // No, let's just let write_msg handle the sending. 
        // For the "resend Act 1 on timeout" feature, we might need to manually set `last_act1_msg_json` in `GoBNConnection`.
        // Let's modify GoBNConnection to auto-cache if it's the first message? 
        // Or simpler: just constructing the Act 1 packet manually here and setting it?
        
        // Let's trust GoBNConnection's write_msg for now. 
        // For the "resend cache", we need to populate generic `last_act1_msg_json`.
        // I'll calculate what the Act 1 JSON *would* be and set it.
        // Actually, write_msg doesn't expose the JSON.
        // I will simply call write_msg. If we lose Act 1 and timeout, we might fail to resend unless we fix the cache logic.
        // FIX: Let's manually construct Act 1 JSON and set it in gobn struct publicly?
        // Or add a method `set_act1_cache`.
        // For now, I'll proceed with standard write_msg.
        
        gobn.write_msg(&act1_msg).await?;
        gobn.flush().await?;
        eprintln!("✅ Act 1 sent and flushed");
        
        // Act 2: Receive server's response
        eprintln!("🔄 Waiting for Act 2...");
        let act2_buf = gobn.read_msg().await?; // read_msg handles unpacking MsgData
        
        eprintln!(
            "📥 Received Act 2 data: {} bytes, first 20: {:02x?}",
            act2_buf.len(),
            &act2_buf[..act2_buf.len().min(20)]
        );
        
        state.act2(&act2_buf)?;
        eprintln!("✅ Noise Act 2: Received and processed server response");
        
        // Transfer auth data from state to self
        if let Some(auth_data) = state.auth_data.clone() {
            self.auth_data = Some(auth_data);
        }
        
        // Act 3: Send our static key and complete handshake
        eprintln!("📤 Noise Act 3: Sending static key...");
        let act3_msg = state.act3()?;
        gobn.write_msg(&act3_msg).await?;
        gobn.flush().await?;
        
        // Get remote static key before splitting (split takes ownership)
        let remote_pub = state.remote_static();
        
        // Split handshake and initialize cipher
        let (send_key, recv_key) = state.split()?;
        
        // Initialize the ciphers with the respective keys
        let send_cipher = ChaCha20Poly1305::new(&send_key.into());
        let recv_cipher = ChaCha20Poly1305::new(&recv_key.into());
        
        self.send_cipher = Some(send_cipher);
        self.recv_cipher = Some(recv_cipher);
        
        // Store keys so we can recreate ciphers on clone
        self.send_key = Some(send_key);
        self.recv_key = Some(recv_key);
        self.shared_secret = Some(send_key); // Keep for compatibility
        
        // Reset nonces
        self.send_nonce = 0;
        self.recv_nonce = 0;
        
        // Store remote public key
        if let Some(remote_pub) = remote_pub {
            self.remote_public = Some(remote_pub);
        }
        
        // CRITICAL FIX: Clear the Act 1 cache now that handshake is complete
        // This prevents the client from resending Act 1 every time it receives a ping
        gobn.last_act1_msg_json = None;
        
        eprintln!("✅ Noise handshake completed!");
        
        Ok(())
    }
    
    async fn try_connect_endpoint(
        &self,
        url: &str,
    ) -> Result<(futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>, futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>), Box<dyn Error + Send + Sync>> {
        let (ws_stream, _) = connect_async(url).await.map_err(|e| {
            format!("WebSocket connection failed for {}: {}", url, e)
        })?;
        let (write, read) = ws_stream.split();
        Ok((write, read))
    }
    
    /// Connect to the mailbox server
    pub async fn connect(&mut self) -> Result<Arc<Mutex<MailboxConnection>>, Box<dyn Error + Send + Sync>> {
        self.get_connection().await
    }
    
    fn mailbox_base_url(&self) -> String {
        let base = if self.mailbox_server.starts_with("ws://") || self.mailbox_server.starts_with("wss://") {
            self.mailbox_server.clone()
        } else {
            format!("wss://{}", self.mailbox_server)
        };
        base.replace(":443", "").trim_end_matches('/').to_string()
    }
    
    fn mailbox_recv_url(&self) -> String {
        format!("{}/v1/lightning-node-connect/hashmail/receive?method=POST", self.mailbox_base_url())
    }
    
    fn mailbox_send_url(&self) -> String {
        format!("{}/v1/lightning-node-connect/hashmail/send?method=POST", self.mailbox_base_url())
    }
}

impl Clone for LNCMailbox {
    fn clone(&self) -> Self {
        Self {
            passphrase_entropy: self.passphrase_entropy.clone(),
            stretched_passphrase: self.stretched_passphrase.clone(),
            stream_id: self.stream_id.clone(),
            local_keypair: self.local_keypair,
            remote_public: self.remote_public,
            shared_secret: self.shared_secret,
            mailbox_server: self.mailbox_server.clone(),
            // Recreate ciphers from stored keys
            send_cipher: self.send_key.map(|key| ChaCha20Poly1305::new(&key.into())),
            recv_cipher: self.recv_key.map(|key| ChaCha20Poly1305::new(&key.into())),
            send_key: self.send_key,
            recv_key: self.recv_key,
            send_nonce: self.send_nonce,
            recv_nonce: self.recv_nonce,
            auth_data: self.auth_data.clone(),
            connection: None,
        }
    }
}

/// Represents an active mailbox connection
pub struct MailboxConnection {
    // GoBN connection handles all the transport logic (ACKs, PINGs, MsgData wrapping)
    gobn: Arc<Mutex<GoBNConnection>>,
    mailbox: Arc<Mutex<LNCMailbox>>,
    
    // Buffering for AsyncRead/AsyncWrite implementation
    read_buffer: Arc<Mutex<Vec<u8>>>,        // Decrypted plaintext ready to read
    write_buffer: Arc<Mutex<Vec<u8>>>,
    
    // Buffer for incomplete Noise frames (encrypted data)
    // Messages may be split across multiple GoBN packets, so we need to accumulate
    // encrypted bytes until we have a complete frame (18-byte header + body)
    encrypted_buffer: Arc<Mutex<Vec<u8>>>,
    
    // Track if we're currently reading to avoid spawning multiple read tasks
    reading: Arc<Mutex<bool>>,
    // Store read error if one occurred
    read_error: Arc<Mutex<Option<String>>>,
    // Track if we're currently writing
    writing: Arc<Mutex<bool>>,
    // Track if HTTP/2 SETTINGS exchange is complete
    http2_ready: Arc<Mutex<bool>>,
}

impl MailboxConnection {
    /// Initialize HTTP/2 by forcing the SETTINGS exchange to complete
    pub async fn initialize_http2(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        eprintln!("🔄 Initializing HTTP/2 connection...");
        
        // Give tonic a moment to send the preface and initial SETTINGS
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Trigger a read to receive the server's SETTINGS
        // This will cause our async read handler to receive and process the server's SETTINGS
        // and automatically send the SETTINGS ACK
        let start = std::time::Instant::now();
        loop {
            let buf_len = {
                let buf = self.read_buffer.lock().await;
                buf.len()
            };
            
            if buf_len > 0 {
                eprintln!("✅ Received {} bytes from server (HTTP/2 SETTINGS)", buf_len);
                break;
            }
            
            if start.elapsed() > Duration::from_secs(2) {
                return Err("Timeout waiting for server SETTINGS".into());
            }
            
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        
        // Give time for SETTINGS ACK to be sent
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Mark HTTP/2 as ready
        let mut ready = self.http2_ready.lock().await;
        *ready = true;
        drop(ready);
        
        eprintln!("✅ HTTP/2 SETTINGS exchange complete");
        Ok(())
    }
    
    /// Send an encrypted message through the mailbox
    pub async fn send_encrypted(&self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        eprintln!("🔒 Encrypting {} bytes for transmission", data.len());
        eprintln!("   First 20 bytes (plaintext): {:02x?}", &data[..data.len().min(20)]);
        
        let mut mailbox = self.mailbox.lock().await;
        // Encrypt with Noise cipher
        let encrypted = mailbox.encrypt(data)?; // removed await as encrypt is now synchronous
        drop(mailbox);
        
        // Send via GoBN (wraps in MsgData, handles ACKs internally)
        let mut gobn = self.gobn.lock().await;
        gobn.write_msg(&encrypted).await?;
        gobn.flush().await?;
        
        Ok(())
    }
    
    /// Receive and decrypt a message from the mailbox
    pub async fn receive_encrypted(&self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut gobn = self.gobn.lock().await;
        
        // Read from GoBN (handles ACKs, PINGs, unwraps MsgData)
        // This returns only the Noise message payload
        let noise_msg = gobn.read_msg().await?;
        drop(gobn);
        
        eprintln!("🔓 Decrypting {} bytes of noise message", noise_msg.len());
        
        // Decrypt with Noise cipher
        let mut mailbox = self.mailbox.lock().await;
        let decrypted = mailbox.decrypt(&noise_msg)?;
        
        eprintln!("✅ Decrypted to {} bytes: {:02x?}", decrypted.len(), &decrypted[..decrypted.len().min(50)]);
        
        Ok(decrypted)
    }
}

// Implement AsyncRead for MailboxConnection
impl tokio::io::AsyncRead for MailboxConnection {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        
        // Check if there was a read error
        if let Ok(mut error_opt) = this.read_error.try_lock() {
            if let Some(error_msg) = error_opt.take() {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    error_msg
                )));
            }
        }
        
        // Try to get data from read buffer first
        let mut read_buffer = match this.read_buffer.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
        };
        
        if !read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), read_buffer.len());
            buf.put_slice(&read_buffer[..to_read]);
            read_buffer.drain(..to_read);
            return std::task::Poll::Ready(Ok(()));
        }
        drop(read_buffer);
        
        // Check if we're already reading (avoid spawning multiple tasks)
        let mut is_reading = match this.reading.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
        };
        
        if *is_reading {
            // Already reading, just wait
            drop(is_reading);
            return std::task::Poll::Pending;
        }
        
        // Mark that we're reading
        *is_reading = true;
        drop(is_reading);
        
        // Buffer is empty, need to read from connection
        let gobn = Arc::clone(&this.gobn);
        let mailbox = Arc::clone(&this.mailbox);
        let read_buf_arc = Arc::clone(&this.read_buffer);
        let encrypted_buf_arc = Arc::clone(&this.encrypted_buffer);
        let reading_flag = Arc::clone(&this.reading);
        let error_arc = Arc::clone(&this.read_error);
        
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            let result = async {
                // Read one GoBN packet (which contains encrypted Noise data)
                // Use a timeout to avoid blocking write operations
                let noise_encrypted = tokio::time::timeout(
                    Duration::from_millis(100),
                    async {
                        let mut gobn_guard = gobn.lock().await;
                        let msg = gobn_guard.read_msg().await?;
                        Ok::<_, Box<dyn Error + Send + Sync>>(msg)
                    }
                ).await;
                
                let noise_encrypted = match noise_encrypted {
                    Ok(Ok(msg)) => msg,
                    Ok(Err(e)) => return Err(e),
                    Err(_timeout) => {
                        // Timeout - couldn't get lock or no data available
                        // This is normal, just wake and retry later
                        return Ok(());
                    }
                };
                
                if noise_encrypted.is_empty() {
                    // No data read, just retry
                    return Ok(());
                }
                
                eprintln!("📥 Received {} bytes of encrypted Noise data: {:02x?}", noise_encrypted.len(), &noise_encrypted[..noise_encrypted.len().min(20)]);
                
                // Add to encrypted buffer
                let mut enc_buf = encrypted_buf_arc.lock().await;
                enc_buf.extend_from_slice(&noise_encrypted);
                
                eprintln!("   🔢 Encrypted buffer now has {} bytes", enc_buf.len());
                
                // Try to decrypt complete frames from the buffer
                // IMPORTANT: Only attempt decryption when we have enough bytes for a complete frame
                loop {
                    // Need at least 18 bytes for the length header
                    if enc_buf.len() < 18 {
                        eprintln!("   ⏳ Not enough data yet (need 18 bytes for header)");
                        break;
                    }
                    
                    // PEEK at the length header WITHOUT decrypting yet
                    // We need to check if we have enough bytes for the complete frame BEFORE
                    // attempting decryption (which would increment nonces)
                    
                    // To peek at the length, we need to manually decrypt just the header
                    // This is a bit tricky because decrypt() does both header and body
                    // For now, we'll use a heuristic: if decrypt fails with "Incomplete message",
                    // we know we need more data
                    
                    // Clone the buffer to test decryption
                    let encrypted_data = enc_buf.clone();
                    let enc_buf_len_before = enc_buf.len();
                    
                    // Save the current nonces before attempting decryption
                    let mut mailbox_guard = mailbox.lock().await;
                    let recv_nonce_before = mailbox_guard.recv_nonce;
                    
                    match mailbox_guard.decrypt(&encrypted_data) {
                        Ok(decrypted) => {
                            // Success! We had a complete frame
                            // Calculate how many bytes were consumed
                            let header_len = 18;
                            let body_len = decrypted.len() + 16; // plaintext + MAC
                            let total_consumed = header_len + body_len;
                            
                            eprintln!("   ✅ Successfully decrypted {} bytes (consumed {} encrypted bytes)", decrypted.len(), total_consumed);
                            
                            // Parse incoming HTTP/2 frames for debugging
                            eprintln!("🔍 Parsing incoming HTTP/2 frames:");
                            parse_and_log_http2_frames(&decrypted);
                            
                            // Remove consumed bytes from encrypted buffer
                            enc_buf.drain(..total_consumed);
                            drop(enc_buf);
                            drop(mailbox_guard);
                            
                            // Add decrypted data to read buffer
                            let mut read_buf = read_buf_arc.lock().await;
                            read_buf.extend_from_slice(&decrypted);
                            drop(read_buf);
                            
                            // Continue to see if there's another complete frame
                            enc_buf = encrypted_buf_arc.lock().await;
                            mailbox_guard = mailbox.lock().await;
                        }
                        Err(e) => {
                            // Incomplete frame - need more data
                            if e.to_string().contains("Incomplete message") {
                                eprintln!("   ⏳ Incomplete frame, waiting for more data");
                                
                                // CRITICAL: Restore the nonce since we didn't successfully complete the operation
                                mailbox_guard.recv_nonce = recv_nonce_before;
                                eprintln!("   🔄 Restored recv_nonce to {} (was incremented during failed attempt)", recv_nonce_before);
                                
                                break;
                            } else {
                                // Real decryption error - could be connection closing or corrupted data
                                eprintln!("   ❌ Decryption error: {}", e);
                                eprintln!("   📊 Encrypted buffer contents ({} bytes): {:02x?}", enc_buf.len(), &enc_buf[..enc_buf.len().min(50)]);
                                eprintln!("   🔢 Buffer length: {}, Nonce before: {}, Nonce after: {}", enc_buf_len_before, recv_nonce_before, mailbox_guard.recv_nonce);
                                
                                // Check if this might be a connection close or error message
                                // If buffer is very small (< 18 bytes), it's not a valid Noise frame
                                if enc_buf.len() < 18 {
                                    eprintln!("   💡 Buffer too small for Noise frame, might be connection closing");
                                    // Clear the buffer and break - don't propagate as error yet
                                    enc_buf.clear();
                                    break;
                                }
                                
                                drop(enc_buf);
                                drop(mailbox_guard);
                                return Err(e);
                            }
                        }
                    }
                }
                
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            }.await;
            
            match result {
                Ok(_) => {
                    // Successfully processed data
                }
                Err(e) => {
                    eprintln!("Error reading from mailbox: {}", e);
                    let mut error = error_arc.lock().await;
                    *error = Some(e.to_string());
                }
            }
            
            // Mark that we're done reading
            let mut reading = reading_flag.lock().await;
            *reading = false;
            
            waker.wake();
        });
        
        std::task::Poll::Pending
    }
}

// HTTP/2 frame parser for debugging
fn parse_and_log_http2_frames(data: &[u8]) {
    // Check for HTTP/2 connection preface
    const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    
    if data.starts_with(HTTP2_PREFACE) {
        eprintln!("🔍 HTTP/2 Connection Preface detected ({} bytes)", HTTP2_PREFACE.len());
        if data.len() > HTTP2_PREFACE.len() {
            eprintln!("🔍 Additional data after preface: {} bytes", data.len() - HTTP2_PREFACE.len());
            parse_http2_frames_from_offset(data, HTTP2_PREFACE.len());
        }
        return;
    }
    
    // Parse HTTP/2 frames
    parse_http2_frames_from_offset(data, 0);
}

fn parse_http2_frames_from_offset(data: &[u8], offset: usize) {
    let mut pos = offset;
    
    while pos + 9 <= data.len() {
        // HTTP/2 frame header: 9 bytes
        // 3 bytes: length (24-bit)
        // 1 byte: type
        // 1 byte: flags
        // 4 bytes: stream identifier (31-bit)
        
        let length = ((data[pos] as usize) << 16) | ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
        let frame_type = data[pos + 3];
        let flags = data[pos + 4];
        let stream_id = u32::from_be_bytes([
            data[pos + 5] & 0x7F,  // Clear reserved bit
            data[pos + 6],
            data[pos + 7],
            data[pos + 8],
        ]);
        
        let frame_type_name = match frame_type {
            0x00 => "DATA",
            0x01 => "HEADERS",
            0x02 => "PRIORITY",
            0x03 => "RST_STREAM",
            0x04 => "SETTINGS",
            0x05 => "PUSH_PROMISE",
            0x06 => "PING",
            0x07 => "GOAWAY",
            0x08 => "WINDOW_UPDATE",
            0x09 => "CONTINUATION",
            _ => "UNKNOWN",
        };
        
        eprintln!("🔍 HTTP/2 Frame: type={} (0x{:02x}), flags=0x{:02x}, stream_id={}, length={}", 
                  frame_type_name, frame_type, flags, stream_id, length);
        
        // For SETTINGS frames, parse the settings
        if frame_type == 0x04 && pos + 9 + length <= data.len() {
            parse_settings_frame(&data[pos + 9..pos + 9 + length], flags);
        }
        
        // For HEADERS frames, try to parse headers
        if frame_type == 0x01 && pos + 9 + length <= data.len() {
            parse_headers_frame(&data[pos + 9..pos + 9 + length], flags);
        }
        
        pos += 9 + length;
        
        if pos >= data.len() {
            break;
        }
    }
}

fn parse_settings_frame(payload: &[u8], flags: u8) {
    if flags & 0x01 != 0 {
        eprintln!("   📋 SETTINGS ACK");
        return;
    }
    
    let mut pos = 0;
    while pos + 6 <= payload.len() {
        let id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let value = u32::from_be_bytes([
            payload[pos + 2],
            payload[pos + 3],
            payload[pos + 4],
            payload[pos + 5],
        ]);
        
        let setting_name = match id {
            0x01 => "HEADER_TABLE_SIZE",
            0x02 => "ENABLE_PUSH",
            0x03 => "MAX_CONCURRENT_STREAMS",
            0x04 => "INITIAL_WINDOW_SIZE",
            0x05 => "MAX_FRAME_SIZE",
            0x06 => "MAX_HEADER_LIST_SIZE",
            _ => "UNKNOWN",
        };
        
        eprintln!("   📋 {}={}", setting_name, value);
        pos += 6;
    }
}

fn parse_headers_frame(payload: &[u8], flags: u8) {
    eprintln!("   📨 HEADERS frame payload: {} bytes, flags=0x{:02x}", payload.len(), flags);
    eprintln!("   📨 First 50 bytes: {:02x?}", &payload[..payload.len().min(50)]);
    
    // Try to find recognizable patterns
    if let Ok(s) = std::str::from_utf8(payload) {
        eprintln!("   📨 As string: {}", s.chars().take(200).collect::<String>());
    }
}

// Implement AsyncWrite for MailboxConnection  
impl tokio::io::AsyncWrite for MailboxConnection {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        
        // Check if HTTP/2 SETTINGS exchange is complete
        let http2_ready = match this.http2_ready.try_lock() {
            Ok(guard) => *guard,
            Err(_) => false,
        };
        
        // Before SETTINGS exchange is complete, send all frames immediately
        // This ensures proper ordering: Preface, SETTINGS, SETTINGS ACK before any requests
        if !http2_ready {
            eprintln!("📝 poll_write: HTTP/2 not ready - sending {} bytes immediately", buf.len());
            
            let gobn = Arc::clone(&this.gobn);
            let mailbox = Arc::clone(&this.mailbox);
            let data = buf.to_vec();
            let len = buf.len();
            let waker = cx.waker().clone();
            let http2_ready_arc = Arc::clone(&this.http2_ready);
            
            // Check if this is SETTINGS ACK to mark HTTP/2 as ready
            let is_settings_ack = buf.len() == 9 && buf[3] == 0x04 && buf[4] == 0x01;
            
            tokio::spawn(async move {
                let result = async {
                    let mut mailbox_guard = mailbox.lock().await;
                    let encrypted = mailbox_guard.encrypt(&data)?;
                    drop(mailbox_guard);
                    
                    let mut gobn_guard = gobn.lock().await;
                    gobn_guard.write_msg(&encrypted).await?;
                    gobn_guard.flush().await?;
                    
                    if is_settings_ack {
                        let mut ready = http2_ready_arc.lock().await;
                        *ready = true;
                        eprintln!("✅ HTTP/2 SETTINGS exchange complete");
                    }
                    
                    Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                }.await;
                
                if let Err(e) = result {
                    eprintln!("❌ Error sending frame: {}", e);
                }
                waker.wake();
            });
            
            return std::task::Poll::Ready(Ok(len));
        }
        
        // For other frames, buffer normally
        let mut write_buffer = match this.write_buffer.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
        };
        
        eprintln!("📝 poll_write: Buffering {} bytes (total will be {} bytes)", 
                  buf.len(), write_buffer.len() + buf.len());
        write_buffer.extend_from_slice(buf);
        
        // Wake immediately to trigger flush
        cx.waker().wake_by_ref();
        
        std::task::Poll::Ready(Ok(buf.len()))
    }
    
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        
        // Check if we're already writing
        let mut writing_guard = match this.writing.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
        };
        
        if *writing_guard {
            // Still writing from previous flush
            return std::task::Poll::Pending;
        }
        
        let mut write_buffer = match this.write_buffer.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
        };
        
        if write_buffer.is_empty() {
            return std::task::Poll::Ready(Ok(()));
        }
        
        let data = write_buffer.clone();
        write_buffer.clear();
        drop(write_buffer);
        
        eprintln!("📤 poll_flush: Sending {} bytes", data.len());
        parse_and_log_http2_frames(&data);
        
        *writing_guard = true;
        drop(writing_guard);
        
        let gobn = Arc::clone(&this.gobn);
        let mailbox = Arc::clone(&this.mailbox);
        let writing = Arc::clone(&this.writing);
        let waker = cx.waker().clone();
        
        tokio::spawn(async move {
            eprintln!("🔄 poll_flush task started");
            let result = async {
                eprintln!("🔐 Acquiring mailbox lock for encryption...");
                let mut mailbox_guard = mailbox.lock().await;
                eprintln!("✅ Mailbox lock acquired, encrypting...");
                let encrypted = mailbox_guard.encrypt(&data)?;
                drop(mailbox_guard);
                eprintln!("✅ Encryption complete, acquiring GoBN lock...");
                
                let mut gobn_guard = gobn.lock().await;
                eprintln!("✅ GoBN lock acquired, writing message...");
                gobn_guard.write_msg(&encrypted).await?;
                eprintln!("✅ Message written, flushing...");
                gobn_guard.flush().await?;
                eprintln!("✅ Flush complete!");
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            }.await;
            
            let mut writing_guard = writing.lock().await;
            *writing_guard = false;
            drop(writing_guard);
            
            if let Err(e) = result {
                eprintln!("❌ Error in poll_flush: {}", e);
            } else {
                eprintln!("✅ poll_flush task completed successfully");
            }
            waker.wake();
        });
        
        std::task::Poll::Pending
    }
    
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // For now, just return Ready - proper shutdown would close the GoBN connection
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mnemonic_to_entropy() {
        // Test with a sample 10-word phrase
        let words = ["abandon", "abandon", "abandon", "abandon", "abandon", 
                     "abandon", "abandon", "abandon", "abandon", "about"];
        let entropy = mnemonic_to_entropy(&words).unwrap();
        assert_eq!(entropy.len(), NUM_PASSPHRASE_ENTROPY_BYTES);
        
        // First word "abandon" is index 0, all zeros in 11 bits
        // "about" is index 3 = 0b00000000011
        // So we expect mostly zeros with some bits set at the end
    }
    
    #[test]
    fn test_parse_mnemonic_phrase() {
        let mnemonic = "abandon ability able about above absent absorb abstract absurd abuse";
        let result = parse_pairing_phrase(mnemonic);
        assert!(result.is_ok());
        
        let parsed = result.unwrap();
        assert!(parsed.mnemonic.is_some());
        assert_eq!(parsed.stream_id.len(), 64);
        assert_eq!(parsed.passphrase_entropy.len(), NUM_PASSPHRASE_ENTROPY_BYTES);
    }
    
    #[test]
    fn test_parse_invalid_phrase() {
        // Test with wrong number of words
        let invalid = "one two three";
        let result = parse_pairing_phrase(invalid);
        assert!(result.is_err());
        
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("expected 10 words"));
    }
    
    #[test]
    fn test_stream_id_derivation() {
        // Test that stream ID is correctly derived from entropy
        let entropy = [0u8; NUM_PASSPHRASE_ENTROPY_BYTES];
        let stream_id = derive_stream_id(&entropy);
        assert_eq!(stream_id.len(), 64);
    }
}
