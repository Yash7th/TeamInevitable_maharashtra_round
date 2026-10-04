import datetime
import hashlib
import os
import base64
import streamlit as st
import solcx
from web3 import Web3, EthereumTesterProvider
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

st.set_page_config(
    page_title="ModelLedger | Web3 AI Provenance Tracker",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for clean, professional corporate Web3 aesthetic
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    code, pre, .mono {
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .hero-container {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 24px;
        margin-bottom: 24px;
    }
    
    .vault-unlocked {
        background-color: #064e3b22;
        border: 1px solid #059669;
        border-radius: 8px;
        padding: 20px;
        margin-top: 16px;
        margin-bottom: 20px;
    }
    
    .vault-locked {
        background-color: #7f1d1d22;
        border: 1px solid #dc2626;
        border-radius: 8px;
        padding: 20px;
        margin-top: 16px;
        margin-bottom: 20px;
    }
    
    .detail-pill {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 6px;
        padding: 16px;
        margin-bottom: 12px;
    }
    
    .badge-trusted {
        background-color: #065f46;
        color: #6ee7b7;
        padding: 3px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
        display: inline-block;
        letter-spacing: 0.02em;
    }
    
    .badge-selfasserted {
        background-color: #78350f;
        color: #fcd34d;
        padding: 3px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
        display: inline-block;
        letter-spacing: 0.02em;
    }
    
    .badge-unverifiable {
        background-color: #7f1d1d;
        color: #fca5a5;
        padding: 3px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.8rem;
        display: inline-block;
        letter-spacing: 0.02em;
    }
</style>
""", unsafe_allow_html=True)

# AES Cryptography locked by Image Hash
def encrypt_with_image_hash(plaintext: str, key_32bytes: bytes) -> str:
    """Encrypts plaintext using the 32-byte image hash as the AES-256 key."""
    iv = os.urandom(16)
    cipher = AES.new(key_32bytes, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    payload = iv + encrypted_bytes
    return base64.b64encode(payload).decode('utf-8')

def decrypt_with_image_hash(cipher_b64: str, key_32bytes: bytes) -> str:
    """Decrypts ciphertext using the 32-byte image hash as the key."""
    try:
        raw_payload = base64.b64decode(cipher_b64)
        iv = raw_payload[:16]
        encrypted_data = raw_payload[16:]
        cipher = AES.new(key_32bytes, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted = unpad(decrypted_padded, AES.block_size).decode('utf-8')
        return decrypted
    except Exception:
        return None

# Helper functions for hashing and parsing
def compute_sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def compute_sha256_hex(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()

def string_to_bytes32(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()

def parse_bytes32(hex_or_empty: str) -> bytes:
    clean = hex_or_empty.strip()
    if not clean or clean == "0" or clean == "0x0":
        return bytes(32)
    if clean.startswith("0x") or clean.startswith("0X"):
        clean = clean[2:]
    clean = clean.rjust(64, '0')[:64]
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return bytes(32)

# Blockchain Initialization cached in resource
@st.cache_resource(show_spinner="Compiling Smart Contract and Booting Test Blockchain...")
def init_blockchain_and_contract():
    solcx.install_solc('0.8.20')
    solcx.set_solc_version('0.8.20')
    
    contract_path = os.path.join(os.path.dirname(__file__), "ModelLedger.sol")
    compiled_sol = solcx.compile_files(
        [contract_path],
        output_values=['abi', 'bin'],
        solc_version='0.8.20'
    )
    
    contract_id = f"{contract_path}:ModelLedger"
    if contract_id not in compiled_sol:
        for k in compiled_sol.keys():
            if "ModelLedger" in k:
                contract_id = k
                break
                
    contract_interface = compiled_sol[contract_id]
    abi = contract_interface['abi']
    bytecode = contract_interface['bin']
    
    w3 = Web3(EthereumTesterProvider())
    deployer_account = w3.eth.accounts[0]
    
    ModelLedgerFactory = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = ModelLedgerFactory.constructor().transact({'from': deployer_account})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress
    
    deployed_contract = w3.eth.contract(address=contract_address, abi=abi)
    return w3, deployed_contract, deployer_account, contract_address, abi

# Initialize Web3
w3, contract, deployer, contract_address, abi = init_blockchain_and_contract()

# Sidebar Information
with st.sidebar:
    st.title("ModelLedger")
    st.caption("On-Chain AI Provenance Tracking System")
    
    st.markdown("### Network Status")
    st.info("Local Testnet (EthereumTester) Active")
    st.metric(label="Block Height", value=w3.eth.block_number)
    st.metric(label="Gas Price", value=f"{w3.eth.gas_price} Wei")
    
    st.markdown("---")
    st.markdown("### Security Architecture")
    st.caption("""
    Provenance metadata is encrypted on-chain using AES-256.
    The primary decryption key is strictly the 32-byte SHA-256 hash of the authentic artifact. 
    Any alteration of the artifact modifies the computed hash, leaving the metadata locked.
    """)
    
    st.markdown("---")
    st.markdown("### Contract Details")
    st.caption(f"**Address:** `{contract_address}`")
    st.caption(f"**Publisher:** `{deployer}`")
    st.caption(f"**Solidity Version:** `^0.8.20`")

# Hero Header
st.markdown("""
<div class="hero-container">
    <h1 style="margin:0; font-size: 1.8rem; font-weight: 700; color: #f8fafc;">
        ModelLedger
    </h1>
    <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 0.95rem;">
        Decentralized provenance verification and cryptographic lineage ledger for Generative AI.
    </p>
</div>
""", unsafe_allow_html=True)

# Main Navigation Tabs
tab_register, tab_verify = st.tabs(["Register Artifact", "Verify Provenance"])

TRUST_TIERS = {
    "SelfAsserted (0)": 0,
    "Trusted (1)": 1,
    "Unverifiable (2)": 2
}

TRUST_TIER_NAMES = {
    0: ("SelfAsserted", "badge-selfasserted"),
    1: ("Trusted", "badge-trusted"),
    2: ("Unverifiable", "badge-unverifiable")
}

WELL_KNOWN_MODELS = [
    "Midjourney v6.1",
    "Midjourney v6.0",
    "FLUX.1 [dev]",
    "FLUX.1 [schnell]",
    "FLUX.1 [pro]",
    "Stable Diffusion XL (SDXL 1.0)",
    "Stable Diffusion 3.5 Large",
    "Stable Diffusion 3.5 Medium",
    "Stable Diffusion 1.5",
    "DALL-E 3 (OpenAI)",
    "Google Imagen 3",
    "GPT-4o (OpenAI)",
    "GPT-4o-mini (OpenAI)",
    "Claude 3.5 Sonnet (Anthropic)",
    "Claude 3 Opus (Anthropic)",
    "Gemini 1.5 Pro (Google)",
    "Gemini 1.5 Flash (Google)",
    "Llama 3.3 70B (Meta)",
    "DeepSeek-V3",
    "DeepSeek-R1",
    "Runway Gen-3 Alpha",
    "Kling AI",
    "Sora (OpenAI)",
    "Custom / Other"
]

# ==================== REGISTER TAB ====================
with tab_register:
    st.subheader("Register Artifact and Cryptographically Seal Provenance")
    st.write("Upload an AI artifact. The prompt will be encrypted using the artifact's SHA-256 hash as the 256-bit key.")
    
    with st.form("register_form", clear_on_submit=False):
        col1, col2 = st.columns([1, 1])
        
        with col1:
            uploaded_file = st.file_uploader("Upload Generated Artifact", key="reg_upload")
            prompt_input = st.text_area("Generation Prompt to Encrypt and Seal", placeholder="Enter the generation prompt...", height=130)
            
        with col2:
            selected_model = st.selectbox("AI Generator Model", WELL_KNOWN_MODELS, index=0)
            custom_model_input = st.text_input("Custom Model Name (if 'Custom / Other' selected)", placeholder="e.g. Fine-Tuned LoRA / Custom Pipeline")
            parent_hash_input = st.text_input("Parent Artifact Hash (Optional for derivatives)", placeholder="0x0000... or leave empty for root artifact")
            trust_tier_choice = st.selectbox("Trust Tier Certification", list(TRUST_TIERS.keys()), index=1)
            
        submit_reg = st.form_submit_button("Commit Provenance to Blockchain", use_container_width=True, type="primary")

    if submit_reg:
        model_name = custom_model_input.strip() if selected_model == "Custom / Other" else selected_model
        if not uploaded_file:
            st.error("Please upload an artifact file to hash and register.")
        elif not prompt_input.strip():
            st.error("Generation prompt is required.")
        elif selected_model == "Custom / Other" and not model_name:
            st.error("Please specify the custom model name.")
        else:
            file_bytes = uploaded_file.getvalue()
            img_hash_bytes = compute_sha256_bytes(file_bytes)
            img_hash_hex = compute_sha256_hex(file_bytes)
            
            prompt_hash_bytes = string_to_bytes32(prompt_input)
            prompt_hash_hex = "0x" + hashlib.sha256(prompt_input.encode("utf-8")).hexdigest()
            
            encrypted_prompt_b64 = encrypt_with_image_hash(prompt_input.strip(), img_hash_bytes)
            
            parent_bytes = parse_bytes32(parent_hash_input)
            tier_val = TRUST_TIERS[trust_tier_choice]
            
            try:
                already_reg = contract.functions.isRegistered(img_hash_bytes).call()
                if already_reg:
                    st.warning(f"Artifact already registered on-chain. SHA-256: `{img_hash_hex}`")
                else:
                    tx = contract.functions.registerArtifact(
                        img_hash_bytes,
                        prompt_hash_bytes,
                        encrypted_prompt_b64,
                        model_name.strip(),
                        parent_bytes,
                        tier_val
                    ).transact({'from': deployer})
                    
                    receipt = w3.eth.wait_for_transaction_receipt(tx)
                    
                    st.success("Artifact successfully registered and cryptographically sealed on ModelLedger.")
                    
                    with st.expander("View On-Chain Transaction and Vault Payload", expanded=True):
                        st.markdown(f"**Transaction Hash:** `{receipt.transactionHash.hex()}`")
                        st.markdown(f"**Block Number:** `{receipt.blockNumber}`")
                        st.markdown(f"**Gas Used:** `{receipt.gasUsed}`")
                        st.markdown(f"**Artifact SHA-256 Key (`bytes32`):** `{img_hash_hex}`")
                        st.markdown(f"**Prompt Digest (`bytes32`):** `{prompt_hash_hex}`")
                        st.markdown(f"**Encrypted Prompt Ciphertext:** `{encrypted_prompt_b64[:36]}...`")
                        st.markdown(f"**Model Name:** `{model_name.strip()}`")
                        st.markdown(f"**Parent Lineage Hash:** `0x{parent_bytes.hex()}`")
                        st.markdown(f"**Assigned Trust Tier:** `{trust_tier_choice}`")
                        st.markdown(f"**Publisher Node:** `{deployer}`")
            except Exception as e:
                st.error(f"Smart contract execution error: {str(e)}")

# ==================== VERIFY TAB ====================
with tab_verify:
    st.subheader("Verify Artifact Authenticity and Unlock Provenance Vault")
    st.write("Upload an image or artifact to calculate its cryptographic key. If the hash matches the on-chain ledger, the provenance details will be unlocked.")
    
    verify_file = st.file_uploader("Upload Artifact to Verify and Unlock", key="ver_upload")
    
    if verify_file is not None:
        file_bytes = verify_file.getvalue()
        img_hash_bytes = compute_sha256_bytes(file_bytes)
        img_hash_hex = compute_sha256_hex(file_bytes)
        
        st.markdown(f"**Computed Image Hash (Cryptographic Key):** `{img_hash_hex}`")
        
        exists, model_name, enc_prompt, parent_hash, trust_tier_idx, publisher, timestamp = contract.functions.verifyArtifact(img_hash_bytes).call()
        
        if exists:
            unlocked_prompt = decrypt_with_image_hash(enc_prompt, img_hash_bytes)
            
            tier_name, badge_class = TRUST_TIER_NAMES.get(trust_tier_idx, ("Unknown", "badge-unverifiable"))
            dt_str = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if timestamp > 0 else "N/A"
            parent_hex = f"0x{parent_hash.hex()}"
            
            st.markdown(f"""
            <div class="vault-unlocked">
                <h3 style="color: #10b981; margin: 0 0 8px 0; font-size: 1.3rem;">
                    Provenance Vault Unlocked
                </h3>
                <p style="color: #e2e8f0; font-size: 0.95rem; margin-bottom: 0;">
                    The cryptographic hash of this image matched the on-chain ledger and unlocked the verified provenance record.
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown(f"""
            <div class="detail-pill">
                <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; margin-bottom: 4px;">AI Model Origin</div>
                <div style="font-size: 1.1rem; color: #f8fafc; font-weight: 600;">
                    This image was generated using the {model_name} model.
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            if unlocked_prompt:
                st.markdown(f"""
                <div class="detail-pill">
                    <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; margin-bottom: 4px;">Generation Prompt</div>
                    <div style="font-size: 1.05rem; color: #f1f5f9; background: #020617; padding: 12px; border-radius: 6px; border-left: 3px solid #38bdf8;">
                        {unlocked_prompt}
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.warning("Could not decrypt prompt payload with the provided hash key.")
            
            col_v1, col_v2 = st.columns(2)
            with col_v1:
                st.markdown(f"**Trust Tier:** <span class='{badge_class}'>{tier_name}</span>", unsafe_allow_html=True)
                st.markdown(f"**Registration Timestamp:** `{dt_str}` (epoch: `{timestamp}`)")
                st.markdown(f"**Publisher Node:** `{publisher}`")
            with col_v2:
                st.markdown(f"**Parent Lineage Hash:** `{parent_hex}`")
                st.markdown(f"**Decryption Key Used:** `{img_hash_hex}`")
                st.markdown(f"**Ciphertext on Chain:** `{enc_prompt[:24]}...`")
        else:
            st.markdown(f"""
            <div class="vault-locked">
                <h3 style="color: #ef4444; margin: 0 0 8px 0; font-size: 1.3rem;">
                    TAMPER ALERT: Provenance Details Locked
                </h3>
                <p style="color: #fca5a5; font-size: 0.95rem; margin-bottom: 12px;">
                    The computed SHA-256 hash (<code>{img_hash_hex}</code>) does not match any registered key in the ModelLedger smart contract.
                </p>
                <div style="background: rgba(0, 0, 0, 0.3); padding: 12px; border-radius: 6px; border-left: 3px solid #ef4444;">
                    <strong style="color: #fee2e2;">Cryptographic Lock Notice:</strong>
                    <p style="color: #fecaca; margin: 4px 0 0 0; font-size: 0.9rem;">
                        The model name, generation prompt, and creator lineage are cryptographically locked on-chain.
                        The only key that can unlock this information is the authentic, un-tampered image.
                        Because the image hash differs, all provenance data remains blocked.
                    </p>
                </div>
            </div>
            """, unsafe_allow_html=True)
