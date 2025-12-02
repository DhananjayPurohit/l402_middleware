use std::error::Error;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::{connect_async_with_config, tungstenite::{protocol::Message, handshake::client::generate_key, http::Request}};
use futures_util::{StreamExt, SinkExt};
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
        mailbox_server: "wss://mailbox.terminal.lightning.today".to_string(),
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
        mailbox_server: "wss://mailbox.terminal.lightning.today".to_string(),
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
    cipher: Option<ChaCha20Poly1305>,
    nonce_counter: Arc<RwLock<u64>>,
    connection: Option<Arc<Mutex<MailboxConnection>>>,
}

impl LNCMailbox {
    /// Create a new LNC mailbox connection from pairing data
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
            cipher: None,
            nonce_counter: Arc::new(RwLock::new(0)),
            connection: None,
        })
    }
    
    /// Encrypt a message
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let cipher = self.cipher.as_ref()
            .ok_or("Cipher not initialized. Complete the Noise handshake before encrypting.")?;
        
        let mut counter = self.nonce_counter.write().await;
        let nonce_value = *counter;
        *counter += 1;
        drop(counter);
        
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&nonce_value.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt a message
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let cipher = self.cipher.as_ref()
            .ok_or("Cipher not initialized")?;
        
        if ciphertext.len() < 12 {
            return Err("Ciphertext too short".into());
        }
        
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let encrypted_data = &ciphertext[12..];
        
        let plaintext = cipher.decrypt(nonce, encrypted_data)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        Ok(plaintext)
    }
    
    /// Get the receive SID for client (server-to-client stream)
    /// This is the unchanged 64-byte stream_id
    fn get_receive_sid(&self) -> [u8; 64] {
        let mut sid = [0u8; 64];
        sid.copy_from_slice(&self.stream_id);
        sid
    }
    
    /// Get the send SID for client (client-to-server stream)
    /// This is the 64-byte stream_id with the last byte XORed with 0x01
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
        eprintln!("  Note: SIDs differ only in last byte (XOR 0x01)");
        
        // CRITICAL: LNC only allows a SINGLE authentication attempt per pairing phrase.
        // According to the LNC documentation: "LNC will only allow a single attempt to
        // authenticate this key exchange." This means if the first attempt fails, we cannot
        // retry with the same pairing phrase. We must ensure the first attempt succeeds.
        //
        // CRITICAL: We must wait for the server to be fully ready before attempting connection.
        // The server's Accept() blocks if there's a previous connection. When it returns after
        // the previous connection closes, it creates a NEW GoBN connection. We must ensure
        // no previous connection exists before we start our GoBN handshake.
        //
        // CRITICAL: We must wait for the server to be fully ready before starting the handshake.
        // The server's Accept() blocks if there's a previous connection. When it returns, it
        // creates a NEW GoBN connection. We must ensure no previous connection exists when
        // we start, so the server uses the GoBN connection we establish.
        //
        // According to server logs:
        // - Connections take ~5-6 seconds to close after GoBN completes
        // - Accept() blocks waiting for previous connection to close
        // - We need to wait long enough that any previous connection has closed
        //   AND the server is ready to accept our connection
        //
        // CRITICAL: We must wait until the server is ready (no previous connection blocking Accept()).
        // According to server logs, connections can take ~5-6 seconds to close after GoBN completes.
        // We need to wait long enough that:
        // 1. Any previous connection has fully closed (~5-6 seconds)
        // 2. Server's Accept() has returned (if it was blocking)
        // 3. Server is ready to accept our connection
        // 4. When we connect, the server will use the GoBN connection we establish (not create a new one)
        //
        // We wait 60 seconds to be absolutely sure any previous connection has closed and the server
        // is ready. This is conservative but necessary given the single-attempt limitation.
        eprintln!("⏳ Waiting 60s for litd to be ready and ensure no previous connections exist...");
        eprintln!("⚠️  IMPORTANT: LNC only allows ONE authentication attempt per pairing phrase!");
        eprintln!("   If this attempt fails, you'll need to generate a new pairing phrase.");
        eprintln!("   Waiting 60s ensures any previous connection has fully closed.");
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        
        // Only retry on "stream not found" errors - these indicate the server hasn't
        // registered yet, not an authentication failure. For other errors, we can't retry
        // because the pairing phrase may have been consumed by the failed attempt.
        let max_retries = 10;
        let mut attempt = 0;
        
        loop {
            if attempt > 0 {
                // Only retry if we got "stream not found" - this means the server hasn't
                // registered yet, so the pairing phrase hasn't been consumed.
                // Wait longer to ensure the server has fully registered.
                let delay = 5;
                eprintln!("Retrying mailbox connection (attempt {}/{})... waiting {}s for server to register", attempt + 1, max_retries, delay);
                tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
            }
            
            match self.perform_dual_stream_handshake(&receive_sid, &send_sid).await {
                Ok(conn) => {
                    eprintln!("✅ Successfully completed LNC handshake");
                    return Ok(conn);
                }
                Err(e) => {
                    let error_str = e.to_string();
                    eprintln!("❌ Handshake failed: {}", error_str);
                    
                    // Don't retry on "stream occupied" - another client is connected
                    if error_str.contains("stream occupied") || error_str.contains("already active") {
                        return Err(e);
                    }
                    
                    // Only retry on "stream not found" - this indicates the server hasn't registered yet.
                    // For other errors (like authentication failures), we can't retry because
                    // LNC only allows a single authentication attempt per pairing phrase.
                    let is_stream_not_found = error_str.contains("Stream not found") || error_str.contains("stream not found");
                    
                    if !is_stream_not_found {
                        // This is likely an authentication failure or other non-retryable error.
                        // Since LNC only allows one attempt, we must fail immediately.
                        return Err(format!(
                            "❌ Handshake failed and cannot retry (LNC only allows ONE authentication attempt per pairing phrase).\n\
                            Error: {}\n\n\
                            The pairing phrase may have been consumed by this failed attempt.\n\
                            You'll need to generate a new pairing phrase:\n\
                            litcli sessions add --label 'l402' --type admin",
                            error_str
                        ).into());
                    }
                    
                    attempt += 1;
                    
                    if attempt >= max_retries {
                        return Err(format!(
                            "❌ Stream not found after {} attempts.\n\
                            Stream ID: {}\n\n\
                            The stream ID is correctly derived, but litd hasn't registered it.\n\
                            Make sure:\n\
                            1. litd is running and connected to the mailbox\n\
                            2. Use the pairing phrase immediately after generating it\n\
                            3. The pairing phrase hasn't been used before\n\n\
                            Generate a fresh phrase: litcli sessions add --label 'l402' --type admin",
                            attempt, stream_id_hex
                        ).into());
                    }
                    
                    eprintln!("⏳ Stream not found (attempt {}/{}), litd may still be registering...", attempt, max_retries);
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
    ) -> Result<Arc<Mutex<MailboxConnection>>, Box<dyn Error + Send + Sync>> {
        let recv_url = self.mailbox_recv_url();
        let send_url = self.mailbox_send_url();
        
        
        // Step 1: Open SEND connection first and keep it ready
        eprintln!("🔌 Opening SEND stream: {}", send_url);
        let (mut send_write, _send_read) = self.try_connect_endpoint(&send_url).await
            .map_err(|e| format!("Failed to connect to send endpoint: {}", e))?;
        
        // Step 2: Open RECEIVE connection and subscribe BEFORE sending SYN
        // This ensures we can receive the SYNACK when server sends it
        eprintln!("🔌 Opening RECEIVE stream: {}", recv_url);
        let (mut recv_write, mut recv_read) = self.try_connect_endpoint(&recv_url).await
            .map_err(|e| format!("Failed to connect to receive endpoint: {}", e))?;
        
        // Subscribe to the receive stream (server-to-client = unchanged SID)
        let receive_sid_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &receive_sid[..]);
        let recv_init = format!(r#"{{"stream_id":"{}"}}"#, receive_sid_base64);
        eprintln!("📤 Subscribing to RECEIVE stream (server→client)");
        eprintln!("   Stream ID: {}", hex::encode(&receive_sid[..]));
        recv_write.send(Message::Text(recv_init)).await
            .map_err(|e| format!("Failed to subscribe to receive stream: {}", e))?;
        recv_write.flush().await?;
        
        // Small delay to ensure subscription is processed
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // CRITICAL: Check if server has already created a new GoBN connection by waiting briefly
        // for a SYN. If the server's Accept() returned and created a new GoBN connection, it will
        // be waiting for a SYN. We need to detect this and restart our GoBN handshake.
        // However, we can't easily detect this without starting the handshake. So we proceed
        // with the handshake, but we'll handle the case where the server creates a new GoBN
        // connection after we've completed GoBN (by detecting a new SYN and restarting).
        
        // Step 3: Send GoBN SYN message to the server
        let syn_payload = create_gbn_syn(GBN_N);
        let syn_payload_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &syn_payload);
        let send_sid_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &send_sid[..]);
        
        let send_msg = format!(
            r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
            send_sid_base64, syn_payload_base64
        );
        
        eprintln!("📤 Sending GoBN SYN to server (client→server stream)");
        eprintln!("   SYN payload: {:02x?}", syn_payload);
        eprintln!("   Stream ID: {}", hex::encode(&send_sid[..]));
        send_write.send(Message::Text(send_msg.clone())).await
            .map_err(|e| format!("Failed to send SYN: {}", e))?;
        send_write.flush().await?;
        eprintln!("✅ GoBN SYN sent");
        
        // Step 4: Wait for server's SYN response (server echoes our SYN)
        eprintln!("⏳ Waiting for GoBN SYN from server (timeout: 30s)...");
        let response = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            recv_read.next()
        ).await;
        
        match response {
            Ok(Some(Ok(Message::Text(text)))) => {
                eprintln!("📥 Server response: {}", text);
                
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    // Check for error response
                    if let Some(error) = json.get("error") {
                        let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                        let msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
                        
                        if code == 2 || msg.contains("stream not found") {
                            return Err(format!(
                                "❌ Server send stream not found (code {}).\n\n\
                                The server received our SYN but hasn't created its send stream yet.\n\
                                This might be a timing issue or the server failed to create the stream.\n\n\
                                Stream ID we tried: {}", 
                                code, hex::encode(&receive_sid[..])
                            ).into());
                        }
                        
                        return Err(format!("Mailbox error (code {}): {}", code, msg).into());
                    }
                    
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
                                
                                // Step 4: Send SYNACK back to server to complete GoBN handshake
                                let synack_payload = create_gbn_synack();
                                let synack_payload_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &synack_payload);
                                
                                let synack_msg = format!(
                                    r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                                    send_sid_base64, synack_payload_base64
                                );
                                
                                eprintln!("📤 Sending GoBN SYNACK to server");
                                send_write.send(Message::Text(synack_msg)).await
                                    .map_err(|e| format!("Failed to send SYNACK: {}", e))?;
                                send_write.flush().await?;
                                eprintln!("✅ GoBN handshake complete!");
                                
                                // CRITICAL: The reference Go client sends Act 1 immediately after GoBN handshake completes.
                                // We should do the same - no waiting. The server's ServerHandshake() is called by gRPC
                                // asynchronously, and it will wait for Act 1 with a 5-second timeout. Sending immediately
                                // gives the server maximum time to process Act 1 and send Act 2.
                                // 
                                // If Accept() is still blocking, the server will buffer Act 1 in GoBN until ServerHandshake()
                                // is ready to read it. The GoBN layer handles this automatically.
                                //
                                // Note: If the server creates a new GoBN connection after Accept() returns, we'll handle
                                // it by detecting unexpected packets and responding appropriately. But we don't wait for this
                                // - we proceed immediately with the Noise handshake.
                                eprintln!("🔐 Starting Noise XX handshake with SPAKE2 masking...");
                                
                                // Perform Noise handshake over the GoBN connection
                                match self.perform_noise_handshake(&mut send_write, &mut recv_read, &send_sid_base64).await {
                                    Ok(_) => {
                                        eprintln!("✅ Noise handshake completed successfully!");
                                    }
                                    Err(e) => {
                                        return Err(format!("Noise handshake failed: {}", e).into());
                                    }
                                }
                                
                                // Create connection with initialized cipher
                                let connection = MailboxConnection {
                                    write: Arc::new(Mutex::new(send_write)),
                                    read: Arc::new(Mutex::new(recv_read)),
                                    mailbox: Arc::new(Mutex::new(self.clone())),
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
            Ok(Some(Ok(Message::Binary(data)))) => {
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
                    let check_syn = tokio::time::timeout(
                        tokio::time::Duration::from_secs(10),
                        recv_read.next()
                    ).await;
                    
                    match check_syn {
                        Ok(Some(Ok(Message::Text(text)))) => {
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
                        Ok(Some(Ok(Message::Binary(data)))) => {
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
                            eprintln!("✅ No new GoBN connection detected - proceeding with Noise handshake");
                            // CRITICAL: Even if we didn't detect a new GoBN connection, Accept() might still be blocking.
                            // We need to wait long enough for Accept() to return and ServerHandshake() to be called.
                            // Accept() can block for up to ~9 seconds waiting for a previous connection to close.
                            // We wait 10 seconds to be safe, which gives Accept() time to return and ServerHandshake()
                            // to be called (which has a 5-second timeout for receiving Act 1).
                            eprintln!("⏳ Waiting 10s for Accept() to return and ServerHandshake() to be called (Accept() can block up to ~9s)...");
                            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                        }
                    }
                    
                    // Now perform Noise XX handshake (same as text path)
                    eprintln!("🔐 Starting Noise XX handshake with SPAKE2 masking...");
                    
                    // Perform Noise handshake over the GoBN connection
                    match self.perform_noise_handshake(&mut send_write, &mut recv_read, &send_sid_base64).await {
                        Ok(_) => {
                            eprintln!("✅ Noise handshake completed successfully!");
                        }
                        Err(e) => {
                            return Err(format!("Noise handshake failed: {}", e).into());
                        }
                    }
                    
                    // Create connection with initialized cipher
                    let connection = MailboxConnection {
                        write: Arc::new(Mutex::new(send_write)),
                        read: Arc::new(Mutex::new(recv_read)),
                        mailbox: Arc::new(Mutex::new(self.clone())),
                    };
                    
                    let connection_arc = Arc::new(Mutex::new(connection));
                    self.connection = Some(Arc::clone(&connection_arc));
                    
                    eprintln!("✅ LNC connection fully established!");
                    
                    return Ok(connection_arc);
                }
                
                Err(format!("Unexpected binary response: {} bytes", data.len()).into())
            }
            Ok(Some(Ok(other))) => {
                Err(format!("Unexpected message type: {:?}", other).into())
            }
            Ok(Some(Err(e))) => {
                Err(format!("WebSocket error: {}", e).into())
            }
            Ok(None) => {
                Err("Connection closed unexpectedly".into())
            }
            Err(_) => {
                Err("Timeout (30s) waiting for SYN from server - server may not be responding".into())
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

// Helper struct to adapt WebSocket streams to Read/Write for Noise handshake
struct NoiseReadWrite<'a> {
    send_write: &'a mut futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
    recv_read: &'a mut futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    send_sid_base64: String,
    send_seq: u8,  // Sequence number for GoBN DATA packets
    recv_seq: u8,  // Expected sequence number for received packets
    recv_buffer: Vec<u8>,  // Buffer for reassembling multi-chunk messages
}

impl NoiseReadWrite<'_> {
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
    
    async fn write_all(&mut self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        // CRITICAL: Noise handshake messages must be wrapped in MsgData format first!
        // MsgData format: [version (1 byte)] [payload_length (4 bytes BE)] [payload (N bytes)]
        // ProtocolVersion = 0 for mailbox connections
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
            &msg_data,
        );
        
        eprintln!("📤 Sending GoBN DATA packet: seq={}, msgdata_size={} bytes, gbn_packet_size={} bytes", 
            self.send_seq, msg_data.len(), gbn_packet.len());
        eprintln!("   First 20 bytes of GoBN packet: {:02x?}", &gbn_packet[..gbn_packet.len().min(20)]);
        
        // Increment sequence number for next packet (wrap around at window size N=20)
        self.send_seq = (self.send_seq + 1) % 20;
        
        let payload_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &gbn_packet);
        let msg = format!(
            r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
            self.send_sid_base64, payload_base64
        );
        
        self.send_write.send(Message::Text(msg)).await
            .map_err(|e| format!("Failed to send Noise message: {}", e))?;
        Ok(())
    }
    
    async fn flush(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.send_write.flush().await
            .map_err(|e| format!("Failed to flush: {}", e))?;
        Ok(())
    }
    
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Box<dyn Error + Send + Sync>> {
        use futures_util::StreamExt;
        
        // Keep track of how many control packets we've seen while waiting for DATA
        let mut control_packets_seen = 0;
        
        loop {
            // Use longer timeout for Act 2 since server might need time to process
            let response = tokio::time::timeout(
                tokio::time::Duration::from_secs(60),
                self.recv_read.next()
            ).await
                .map_err(|_| {
                    format!("Timeout waiting for Noise Act 2 response (saw {} control packets while waiting). Server may not have sent Act 2, or connection may have closed.", control_packets_seen)
                })?
                .ok_or("Connection closed while waiting for response")?
                .map_err(|e| format!("WebSocket error while waiting for response: {}", e))?;
            
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
                                
                                eprintln!("📥 Received GoBN message: type=0x{:02x}, len={} bytes, first 10: {:02x?}", 
                                    msg_data[0], msg_data.len(), &msg_data[..msg_data.len().min(10)]);
                                
                                // Check message type
                                match msg_data[0] {
                                    GBN_MSG_DATA => {
                                        // GoBN DATA packet: [DATA, Seq, FinalChunk, IsPing, Payload...]
                                        if msg_data.len() < 4 {
                                            eprintln!("⚠️  Received DATA packet too short ({} bytes), ignoring", msg_data.len());
                                            continue;
                                        }
                                        
                                        let seq = msg_data[1];
                                        let final_chunk = msg_data[2] == GBN_TRUE;
                                        let is_ping = msg_data[3] == GBN_TRUE;
                                        
                                        // Ping packets have no payload - just send ACK and continue
                                        if is_ping {
                                            eprintln!("📥 Received GoBN ping packet (seq {}), sending ACK immediately to keep connection alive", seq);
                                            // Send ACK for ping - CRITICAL to keep connection alive
                                            let ack_packet = create_gbn_ack(seq);
                                            let ack_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ack_packet);
                                            let ack_msg = format!(
                                                r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                                                self.send_sid_base64, ack_base64
                                            );
                                            // Make sure ACK is sent - connection will close if server doesn't get pong
                                            if let Err(e) = self.send_write.send(Message::Text(ack_msg)).await {
                                                eprintln!("⚠️  Failed to send ping ACK: {} - connection may close", e);
                                                return Err(format!("Failed to send ping ACK: {}", e).into());
                                            }
                                            eprintln!("✅ Ping ACK sent successfully");
                                            // Note: We don't increment recv_seq for ping packets
                                            continue; // Ping packets have no payload, continue waiting for Act 2
                                        }
                                        
                                        // Check if packet has payload
                                        if msg_data.len() < 5 {
                                            eprintln!("⚠️  Received DATA packet without payload ({} bytes), ignoring", msg_data.len());
                                            continue;
                                        }
                                        
                                        let payload = &msg_data[4..];
                                        eprintln!("📥 Received DATA packet: seq={}, final_chunk={}, is_ping={}, payload_len={} bytes", 
                                            seq, final_chunk, is_ping, payload.len());
                                        
                                        // Check if this is the expected sequence number
                                        // For the first DATA packet after handshake (Act 2), server should send seq 0
                                        // Be more lenient: if buffer is empty, accept any sequence number for first packet
                                        if seq != self.recv_seq {
                                            eprintln!("⚠️  Received DATA packet with seq {} (expected {}), checking if acceptable...", seq, self.recv_seq);
                                            // If we haven't received any data yet (buffer is empty), accept any seq as first packet
                                            // This handles cases where sequence numbers might be slightly out of sync
                                            if self.recv_buffer.is_empty() {
                                                eprintln!("📥 Accepting seq {} as first packet (buffer empty, resetting expected seq)", seq);
                                                self.recv_seq = seq; // Reset to match what server actually sent
                                            } else {
                                                eprintln!("⚠️  Rejecting out-of-order packet (buffer has {} bytes, expected seq {}, got seq {})", 
                                                    self.recv_buffer.len(), self.recv_seq, seq);
                                                // Don't continue - we might want to see what the payload is for debugging
                                                // But for now, continue to avoid blocking
                                                continue;
                                            }
                                        }
                                        
                                        eprintln!("✅ Accepting DATA packet with matching sequence number (seq={})", seq);
                                        
                                        // Increment expected sequence number
                                        self.recv_seq = (self.recv_seq + 1) % 20;
                                        
                                        // Send ACK back
                                        let ack_packet = create_gbn_ack(seq);
                                        let ack_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ack_packet);
                                        let ack_msg = format!(
                                            r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                                            self.send_sid_base64, ack_base64
                                        );
                                        // Best effort ACK - don't fail if it doesn't send
                                        let _ = self.send_write.send(Message::Text(ack_msg)).await;
                                        
                                        // Append payload to reassembly buffer
                                        self.recv_buffer.extend_from_slice(payload);
                                        
                                        // If this is the final chunk, process the complete message
                                        if final_chunk {
                                            let complete_msgdata = std::mem::take(&mut self.recv_buffer);
                                            
                                            // CRITICAL: Unwrap MsgData format
                                            match self.unwrap_msgdata(&complete_msgdata) {
                                                Ok(noise_payload) => {
                                                    let len = noise_payload.len().min(buf.len());
                                                    buf[..len].copy_from_slice(&noise_payload[..len]);
                                                    return Ok(len);
                                                }
                                                Err(e) => {
                                                    eprintln!("⚠️  Failed to unwrap MsgData: {}", e);
                                                    continue;  // Skip this packet and wait for next
                                                }
                                            }
                                        }
                                        
                                        // Not the final chunk, continue waiting for more chunks
                                        continue;
                                    }
                                    GBN_MSG_ACK => {
                                        // ACK message - ignore for now (could implement ACK tracking if needed)
                                        control_packets_seen += 1;
                                        eprintln!("📥 Received ACK packet (seq {}), continuing to wait for DATA packet with Act 2... (seen {} control packets)", 
                                            if msg_data.len() > 1 { msg_data[1] } else { 255 },
                                            control_packets_seen);
                                        continue;
                                    }
                                    GBN_MSG_FIN => {
                                        // FIN message - connection is being closed
                                        eprintln!("📥 Received FIN packet, connection closing (saw {} control packets before FIN)", control_packets_seen);
                                        return Err(format!("Connection closed by server (FIN) - server closed connection before sending Act 2. Control packets seen: {}", control_packets_seen).into());
                                    }
                                    GBN_MSG_SYN | GBN_MSG_SYNACK => {
                                        // These should have been handled during GoBN handshake
                                        eprintln!("⚠️  Received {} after handshake, ignoring", if msg_data[0] == GBN_MSG_SYN { "SYN" } else { "SYNACK" });
                                        continue;
                                    }
                                    _ => {
                                        // Unknown message type - might be raw Noise data (shouldn't happen after handshake)
                                        eprintln!("⚠️  Received unknown message type 0x{:02x}, treating as raw data", msg_data[0]);
                                        let len = msg_data.len().min(buf.len());
                                        buf[..len].copy_from_slice(&msg_data[..len]);
                                        return Ok(len);
                                    }
                                }
                            }
                        }
                    } else {
                        // Not valid JSON - might be a plain error message or unexpected format
                        eprintln!("⚠️  Received non-JSON text message (first 100 chars): {}", 
                            text.chars().take(100).collect::<String>());
                        // Continue waiting - might be some other message format
                    }
                    // Continue waiting for valid DATA packet
                    continue;
                }
                Message::Binary(data) => {
                    // Binary messages - check if it's a GoBN packet
                    if data.is_empty() {
                        continue;
                    }
                    
                    match data[0] {
                        GBN_MSG_DATA => {
                            if data.len() < 5 {
                                continue;
                            }
                            let seq = data[1];
                            let final_chunk = data[2] == 0x01;
                            let is_ping = data[3];
                            let payload = &data[4..];
                            
                            // Handle ping packets
                            if is_ping == 0x01 {
                                // Send ACK for ping
                                let ack_packet = vec![GBN_MSG_ACK, seq];
                                let ack_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ack_packet);
                                let ack_msg = format!(
                                    r#"{{"desc":{{"stream_id":"{}"}},"msg":"{}"}}"#,
                                    self.send_sid_base64, ack_base64
                                );
                                let _ = self.send_write.send(Message::Text(ack_msg)).await;
                                continue;
                            }
                            
                            if seq != self.recv_seq {
                                continue;
                            }
                            
                            self.recv_seq = (self.recv_seq + 1) % 20;
                            
                            // Append to reassembly buffer
                            self.recv_buffer.extend_from_slice(payload);
                            
                            // If final chunk, unwrap MsgData and return complete message
                            if final_chunk {
                                let complete_msgdata = std::mem::take(&mut self.recv_buffer);
                                match self.unwrap_msgdata(&complete_msgdata) {
                                    Ok(noise_payload) => {
                                        let len = noise_payload.len().min(buf.len());
                                        buf[..len].copy_from_slice(&noise_payload[..len]);
                                        return Ok(len);
                                    }
                                    Err(e) => {
                                        eprintln!("⚠️  Failed to unwrap MsgData from binary message: {}", e);
                                        continue;  // Skip this packet and wait for next
                                    }
                                }
                            }
                            
                            // Continue waiting for more chunks
                            continue;
                        }
                        _ => {
                            // Treat as raw data
                            let len = data.len().min(buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            return Ok(len);
                        }
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
    
    version: u8,
}

impl NoiseHandshakeState {
    fn new(local_keypair: &Keypair, passphrase_entropy: Vec<u8>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let secp = Secp256k1::new();
        
        // Initialize protocol name: "Noise_XXeke+SPAKE2_secp256k1_ChaChaPoly_SHA256"
        let protocol_name = b"Noise_XXeke+SPAKE2_secp256k1_ChaChaPoly_SHA256";
        let handshake_digest = Sha256::digest(protocol_name);
        let chaining_key = handshake_digest.into();
        
        // Mix in prologue
        let prologue_hash = Sha256::digest([&handshake_digest[..], LIGHTNING_NODE_CONNECT_PROLOGUE].concat());
        let handshake_digest: [u8; 32] = prologue_hash.into();
        
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
            cipher: None,
            version: 0,
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
        self.mix_hash(&ephem_pub_bytes);
        
        // Mask ephemeral with SPAKE2
        let masked_ephem = spake2_mask(
            &self.local_ephemeral.as_ref().unwrap().public_key(),
            &self.passphrase_entropy,
        )?;
        
        // Act 1 message: [version, masked_ephemeral_pubkey]
        let mut msg = vec![self.version];
        msg.extend_from_slice(&masked_ephem.serialize());
        
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
        
        // Read and decrypt payload (if any)
        offset += encrypted_static_size;
        if offset < data.len() {
            let payload_size = data.len() - offset;
            if payload_size > 16 { // Has MAC
                let _payload = self.decrypt_and_hash(&data[offset..])?;
                // Store auth data if needed (currently not used)
            }
        }
        
        Ok(())
    }
    
    fn act3(&mut self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // Act 3: [version, s, se]
        // s: our static key (encrypted)
        // se: ECDH(remote_ephemeral, local_static) - computed, not sent
        
        // Compute se (ECDH)
        let se = self.ecdh(
            &self.remote_ephemeral.unwrap(),
            &self.local_keypair,
        )?;
        self.mix_key(&se);
        
        // Encrypt our static key
        let static_key_bytes = self.local_keypair.public_key().serialize();
        let encrypted_static = self.encrypt_and_hash(&static_key_bytes);
        
        // Act 3 message: [version, encrypted_static, encrypted_payload(MAC only)]
        let mut msg = vec![self.version];
        msg.extend_from_slice(&encrypted_static);
        
        // Add empty payload (just MAC)
        let empty_payload = self.encrypt_and_hash(&[]);
        msg.extend_from_slice(&empty_payload);
        
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
        let empty: [u8; 0] = [];
        let hk = Hkdf::<Sha256>::new(None, &self.chaining_key);
        let mut new_ck = [0u8; 32];
        let mut new_temp_key = [0u8; 32];
        
        hk.expand(input, &mut new_ck)
            .expect("HKDF should not fail");
        hk.expand(input, &mut new_temp_key)
            .expect("HKDF should not fail");
        
        self.chaining_key = new_ck;
        self.temp_key = new_temp_key;
        
        // Initialize cipher with temp key
        self.cipher = Some(ChaCha20Poly1305::new(&self.temp_key.into()));
    }
    
    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = self.cipher.as_ref()
            .expect("Cipher should be initialized before encrypt_and_hash");
        
        // Use handshake digest as associated data
        let nonce = Nonce::from_slice(&[0u8; 12]); // Nonce starts at 0 during handshake
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .expect("Encryption should not fail");
        
        // Mix ciphertext into hash
        self.mix_hash(&ciphertext);
        
        ciphertext
    }
    
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let cipher = self.cipher.as_ref()
            .ok_or("Cipher not initialized")?;
        
        // Use handshake digest as associated data
        let nonce = Nonce::from_slice(&[0u8; 12]); // Nonce starts at 0 during handshake
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        // Mix ciphertext into hash
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
    
    // Parse SPAKE2 generator point N
    let n_bytes = hex::decode(SPAKE2_N_HEX)
        .map_err(|e| format!("Failed to decode SPAKE2 N: {}", e))?;
    
    // Convert secp256k1 PublicKey to k256 format for point arithmetic
    let e_bytes = e.serialize();
    let e_k256_point = k256::EncodedPoint::from_bytes(&e_bytes)
        .map_err(|e| format!("Invalid ephemeral key: {}", e))?;
    let e_projective = ProjectivePoint::from_encoded_point(&e_k256_point);
    let e_projective = Option::<ProjectivePoint>::from(e_projective)
        .ok_or("Failed to convert ephemeral to projective point")?;
    
    let n_k256_point = k256::EncodedPoint::from_bytes(&n_bytes)
        .map_err(|e| format!("Failed to parse SPAKE2 N: {}", e))?;
    let n_projective = ProjectivePoint::from_encoded_point(&n_k256_point);
    let n_projective = Option::<ProjectivePoint>::from(n_projective)
        .ok_or("Failed to convert N to projective point")?;
    
    // Convert passphrase entropy to scalar
    use k256::elliptic_curve::ff::PrimeField;
    let pw_hash = Sha256::digest(passphrase_entropy);
    let pw_hash_array: [u8; 32] = pw_hash.into();
    let pw_scalar_ct = Scalar::from_repr(pw_hash_array.into());
    let pw_scalar = Option::<Scalar>::from(pw_scalar_ct)
        .ok_or("Invalid scalar representation")?;
    
    // Compute N * pw (scalar multiplication)
    let n_times_pw = n_projective * pw_scalar;
    
    // Add: e + (N * pw) using point addition
    let masked_projective = e_projective + n_times_pw;
    
    // Convert back to compressed public key format
    let masked_point = masked_projective.to_encoded_point(true); // compressed
    let masked_bytes = masked_point.as_bytes();
    
    // Convert back to secp256k1 PublicKey
    PublicKey::from_slice(masked_bytes)
        .map_err(|e| format!("Failed to convert masked point to PublicKey: {}", e).into())
}

impl LNCMailbox {
    /// Perform Noise XX handshake with SPAKE2 masking over GoBN connection
    async fn perform_noise_handshake(
        &mut self,
        send_write: &mut futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
        recv_read: &mut futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
        send_sid_base64: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        use std::io::{Read, Write};
        
        eprintln!("🔐 Starting Noise XX handshake...");
        
        // Create a read/write adapter for the WebSocket streams
        // This will handle sending/receiving Noise handshake messages over GoBN
        // Note: After GoBN handshake, both sides start with seq 0 for their first DATA packet
        let mut noise_rw = NoiseReadWrite {
            send_write,
            recv_read,
            send_sid_base64: send_sid_base64.to_string(),
            send_seq: 0,  // Start with sequence number 0 (we send Act 1 with seq 0)
            recv_seq: 0,  // Expect sequence number 0 for first packet from server (Act 2)
            recv_buffer: Vec::new(),  // Initialize empty buffer for reassembling chunks
        };
        eprintln!("📋 NoiseReadWrite initialized: send_seq=0, recv_seq=0 (expecting Act 2 with seq 0)");
        
        // Initialize Noise handshake state with raw passphrase entropy (not stretched)
        // The stretched passphrase is only used for stream ID derivation, not for SPAKE2
        let mut state = NoiseHandshakeState::new(
            &self.local_keypair,
            self.passphrase_entropy.clone(),
        )?;
        
        // Act 1: Send masked ephemeral (me)
        eprintln!("📤 Noise Act 1: Sending masked ephemeral key...");
        let act1_msg = state.act1()?;
        eprintln!("📤 Act 1 message size: {} bytes, first 20: {:02x?}", act1_msg.len(), &act1_msg[..act1_msg.len().min(20)]);
        noise_rw.write_all(&act1_msg).await?;
        noise_rw.flush().await?;
        eprintln!("✅ Act 1 sent and flushed");
        
        // No delay needed - the server will process Act 1 and send Act 2 when ready.
        // The GoBN layer will buffer Act 2 until we read it.
        
        // Act 2: Receive server's ephemeral, static key, and perform ECDH
        // Use a longer timeout since the server might need time to process Act 1
        // and return from Accept() before ServerHandshake() is called
        eprintln!("⏳ Noise Act 2: Waiting for server response (expecting DATA packet with Act 2, timeout: 60s)...");
        let mut act2_buf = vec![0u8; 500]; // Max size for act 2
        let act2_len = noise_rw.read(&mut act2_buf).await?;
        act2_buf.truncate(act2_len);
        eprintln!("📥 Received Act 2 data: {} bytes, first 20: {:02x?}", act2_len, &act2_buf[..act2_len.min(20)]);
        
        state.act2(&act2_buf)?;
        eprintln!("✅ Noise Act 2: Received and processed server response");
        
        // Act 3: Send our static key and complete handshake
        eprintln!("📤 Noise Act 3: Sending static key...");
        let act3_msg = state.act3()?;
        noise_rw.write_all(&act3_msg).await?;
        noise_rw.flush().await?;
        
        // Get remote static key before splitting (split takes ownership)
        let remote_pub = state.remote_static();
        
        // Split handshake and initialize cipher
        let (send_key, _recv_key) = state.split()?;
        
        // Initialize the cipher with the send key (we'll use send key for encryption)
        let cipher = ChaCha20Poly1305::new(&send_key.into());
        self.cipher = Some(cipher);
        self.shared_secret = Some(send_key);
        
        // Store remote public key
        if let Some(remote_pub) = remote_pub {
            self.remote_public = Some(remote_pub);
        }
        
        eprintln!("✅ Noise handshake completed!");
        
        Ok(())
    }
    
    async fn try_connect_endpoint(
        &self,
        url: &str,
    ) -> Result<(futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>, futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>), Box<dyn Error + Send + Sync>> {
        // Note: Don't set Sec-WebSocket-Protocol as the mailbox server doesn't expect it
        let request = Request::builder()
            .uri(url)
            .header("Host", "mailbox.terminal.lightning.today")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .body(())
            .map_err(|e| format!("Failed to build request: {}", e))?;
        
        let (ws_stream, response) = connect_async_with_config(request, None, false).await
            .map_err(|e| format!("Failed to connect to {}: {}", url, e))?;
        eprintln!("✅ Connected (HTTP status: {})", response.status());
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
            cipher: self.shared_secret.map(|key| ChaCha20Poly1305::new(&key.into())),
            nonce_counter: Arc::clone(&self.nonce_counter),
            connection: None,
        }
    }
}

/// Represents an active mailbox connection
pub struct MailboxConnection {
    write: Arc<Mutex<futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        Message
    >>>,
    read: Arc<Mutex<futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    >>>,
    mailbox: Arc<Mutex<LNCMailbox>>,
}

impl MailboxConnection {
    /// Send an encrypted message through the mailbox
    pub async fn send_encrypted(&self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mailbox = self.mailbox.lock().await;
        let encrypted = mailbox.encrypt(data).await?;
        drop(mailbox);
        
        let mut write = self.write.lock().await;
        write.send(Message::Binary(encrypted)).await
            .map_err(|e| format!("Failed to send message: {}", e))?;
        
        Ok(())
    }
    
    /// Receive and decrypt a message from the mailbox
    pub async fn receive_encrypted(&self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut read = self.read.lock().await;
        
        match read.next().await {
            Some(Ok(Message::Binary(data))) => {
                drop(read);
                let mailbox = self.mailbox.lock().await;
                let decrypted = mailbox.decrypt(&data)?;
                Ok(decrypted)
            }
            Some(Ok(msg)) => Err(format!("Unexpected message type: {:?}", msg).into()),
            Some(Err(e)) => Err(format!("WebSocket error: {}", e).into()),
            None => Err("Connection closed".into()),
        }
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
