import streamlit as st
import random
from PIL import Image # Import Pillow for image handling
import io # Import io for handling image bytes

# --- RSA Functions (from RSA.ipynb) ---

def is_prime(n, k=5):
    """
    Miller-Rabin primality test.
    Returns True if n is probably prime, False otherwise.
    """
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^s * d
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # Repeat k times
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """
    Generates a probable prime number of the given bit length.
    """
    while True:
        p = random.getrandbits(bits)
        # Ensure the number is odd and within the bit length range
        p |= (1 << bits - 1) | 1 # Set MSB and LSB to 1
        if is_prime(p):
            return p

def gcd(a, b):
    """
    Calculates the Greatest Common Divisor (GCD) of a and b using Euclidean algorithm.
    """
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """
    Calculates the modular multiplicative inverse of a modulo m using Extended Euclidean Algorithm.
    Returns x such that (a * x) % m == 1.
    """
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x = x + m0
    return x

def generate_keypair(bits=1024):
    """
    Generates an RSA public and private key pair.
    Returns ((n, e), (n, d)).
    """
    st.info(f"Step 1: Generating two large prime numbers (p and q) of {bits // 2} bits each...")
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    while p == q: # Ensure p and q are distinct
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    st.success(f"Generated p = {p}\nGenerated q = {q}")
    st.info(f"Step 2: Calculate n = p * q = {n}\n"
            f"Step 3: Calculate Euler's totient function phi(n) = (p-1)*(q-1) = {phi}")

    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    st.info("Step 4: Choose public exponent (e) such that 1 < e < phi and gcd(e, phi) = 1.")
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # Calculate d, the modular multiplicative inverse of e modulo phi
    st.info("Step 5: Calculate private exponent (d) as the modular multiplicative inverse of e modulo phi.")
    d = mod_inverse(e, phi)

    st.success(f"Public exponent (e) = {e}\nPrivate exponent (d) = {d}")

    return ((n, e), (n, d))

# --- Text Encryption/Decryption Functions ---
def encrypt_text(public_key, plaintext):
    """
    Encrypts the plaintext string using the public key.
    Converts string chars to integers, encrypts each, returns list of integers.
    Note: This is a simplified character-by-character encryption for demonstration.
    """
    n, e = public_key
    encrypted_chars_as_ints = []
    
    for char in plaintext:
        char_as_int = ord(char)
        if char_as_int >= n:
            st.error(f"Error: Character '{char}' (ASCII: {char_as_int}) is too large for the current key (n={n})."
                     " This simplified demo requires `ord(char) < n`. Please consider a larger key size"
                     " or a simpler message (e.g., ASCII characters).")
            return [] 
        encrypted_char = pow(char_as_int, e, n)
        encrypted_chars_as_ints.append(encrypted_char)
    
    return encrypted_chars_as_ints

def decrypt_text(private_key, ciphertext_ints):
    """
    Decrypts the ciphertext (list of integers) back to a string using the private key.
    """
    n, d = private_key
    decrypted_chars = []
    for char_code in ciphertext_ints:
        decrypted_char_int = pow(char_code, d, n)
        decrypted_chars.append(chr(decrypted_char_int))
    return "".join(decrypted_chars)

# --- Image Encryption/Decryption Functions (byte-by-byte for demo) ---

def encrypt_bytes(public_key, data_bytes):
    """
    Encrypts a sequence of bytes (e.g., image data) using the public key.
    Converts each byte to an integer, encrypts it, returns list of integers.
    """
    n, e = public_key
    encrypted_data_ints = []
    
    for byte_val in data_bytes:
        encrypted_byte = pow(byte_val, e, n)
        encrypted_data_ints.append(encrypted_byte)
    
    return encrypted_data_ints

def decrypt_bytes(private_key, ciphertext_ints):
    """
    Decrypts a list of integers back to bytes (e.g., image data) using the private key.
    """
    n, d = private_key
    decrypted_bytes_list = []
    
    for encrypted_int in ciphertext_ints:
        decrypted_byte_int = pow(encrypted_int, d, n)
        # Ensure the decrypted integer is within 0-255 range for a byte
        if not (0 <= decrypted_byte_int <= 255):
            st.error(f"Decryption error: Decrypted value {decrypted_byte_int} is not a valid byte (0-255). "
                     "This indicates a key mismatch or corrupted data.")
            return b"" # Return empty bytes to indicate error
        decrypted_bytes_list.append(decrypted_byte_int.to_bytes(1, 'big')) 
        
    return b"".join(decrypted_bytes_list) # Combine list of bytes into a single bytes object


# --- Streamlit Application ---

st.set_page_config(page_title="RSA & Image Encryption Demo", layout="wide")

st.title("🔐 RSA & Image Encryption Demo with Streamlit")
st.markdown("Developed by Google Gemini based on your `RSA.ipynb` file.")
st.write("This application demonstrates the basic principles of RSA encryption/decryption, with a *simplified* approach to image encryption.")

# Initialize session state for keys and messages
if 'public_key' not in st.session_state:
    st.session_state.public_key = None
if 'private_key' not in st.session_state:
    st.session_state.private_key = None
if 'encrypted_text_msg' not in st.session_state:
    st.session_state.encrypted_text_msg = []
if 'original_text_msg' not in st.session_state:
    st.session_state.original_text_msg = ""
if 'decrypted_text_msg' not in st.session_state:
    st.session_state.decrypted_text_msg = ""
if 'encrypted_image_data' not in st.session_state:
    st.session_state.encrypted_image_data = []
if 'original_image_bytes' not in st.session_state:
    st.session_state.original_image_bytes = None
if 'original_image_type' not in st.session_state:
    st.session_state.original_image_type = None

st.sidebar.header("Navigation")
# Removed "Digital Signature" from the navigation
page = st.sidebar.radio("Go to", ["1. Key Generation", "2. Text Encryption", "3. Text Decryption & Verification", "4. Image Encryption & Decryption"])

# --- Section 1: Key Generation ---
if page == "1. Key Generation":
    st.header("1. Key Generation 🔑")
    st.markdown("Generate a pair of public and private RSA keys. The larger the key size, the more secure, but longer it takes to generate.")
    
    key_bits = st.slider("Select Key Size (bits)", min_value=256, max_value=2048, value=512, step=128)
    st.caption(f"This will generate two primes of {key_bits // 2} bits each, resulting in an `n` of approximately {key_bits} bits.")
    st.session_state.last_key_bits = key_bits # Store key_bits in session state

    if st.button("Generate RSA Key Pair", type="primary"):
        with st.spinner("Generating keys... This may take a moment for larger sizes."):
            public, private = generate_keypair(key_bits)
            st.session_state.public_key = public
            st.session_state.private_key = private
            st.success("Keys generated successfully!")
            
            st.markdown("---")
            st.subheader("Generated Keys:")
            st.write(f"**Public Key (n, e):**")
            st.code(f"n = {public[0]}\ne = {public[1]}")
            st.write(f"**Private Key (n, d):**")
            st.code(f"n = {private[0]}\nd = {private[1]}")
            st.warning("🚨 Keep your private key secret! It's crucial for decrypting.")

# --- Section 2: Text Encryption ---
elif page == "2. Text Encryption":
    st.header("2. Text Encryption 🔒")
    st.write("Enter the message you want to encrypt using the generated public key.")

    if st.session_state.public_key:
        n_pub, e_pub = st.session_state.public_key
        st.info(f"Current Public Key: `(n={n_pub}, e={e_pub})`")
        
        message_to_encrypt = st.text_area(
            "Plaintext Message", 
            st.session_state.original_text_msg if st.session_state.original_text_msg else "Halo, ini adalah pesan rahasia dari Matematika Diskrit!", 
            height=100
        )
        st.session_state.original_text_msg = message_to_encrypt # Update original_text_msg in session state

        if st.button("Encrypt Text Message", type="primary"):
            if not st.session_state.public_key:
                st.warning("🚫 Please generate keys in the 'Key Generation' section first.")
            else:
                encrypted_data = encrypt_text(st.session_state.public_key, message_to_encrypt)
                if encrypted_data: 
                    st.session_state.encrypted_text_msg = encrypted_data
                    st.success("Text message encrypted successfully!")
                    st.subheader("Encrypted Text Message (list of integers):")
                    st.code(str(st.session_state.encrypted_text_msg))
                    st.info("This is a list of integers, each representing an encrypted character.")
                else:
                    st.error("Encryption failed. Please check the error message above regarding character size.")
    else:
        st.warning("🚫 Please generate keys in the 'Key Generation' section first to enable encryption.")


# --- Section 3: Text Decryption & Verification ---
elif page == "3. Text Decryption & Verification":
    st.header("3. Text Decryption & Verification ✅")
    st.write("The encrypted text message from the previous step will be used automatically for decryption.")

    if st.session_state.private_key and st.session_state.encrypted_text_msg:
        n_priv, d_priv = st.session_state.private_key
        st.info(f"Current Private Key: `(n={n_priv}, d={d_priv})`")
        st.write(f"**Encrypted Text Message to Decrypt:**")
        st.code(str(st.session_state.encrypted_text_msg))
        
        if st.button("Decrypt Text Message", type="primary"):
            if not st.session_state.private_key:
                st.warning("🚫 Please generate keys first.")
            elif not st.session_state.encrypted_text_msg:
                st.warning("🚫 No text message to decrypt. Please encrypt a message first.")
            else:
                decrypted_message = decrypt_text(st.session_state.private_key, st.session_state.encrypted_text_msg)
                st.session_state.decrypted_text_msg = decrypted_message
                st.success("Text message decrypted successfully!")
                st.subheader("Decrypted Text Message:")
                st.code(decrypted_message)

                st.markdown("---")
                st.subheader("Verification")
                if st.session_state.original_text_msg == st.session_state.decrypted_text_msg:
                    st.success("🎉 Verification: Decryption Successful! The original text message matches the decrypted message.")
                else:
                    st.error("❌ Verification: Decryption Failed! The original text message DOES NOT match the decrypted message.")
                    st.write(f"**Original Text:** `{st.session_state.original_text_msg}`")
                    st.write(f"**Decrypted Text:** `{st.session_state.decrypted_text_msg}`")
    else:
        if not st.session_state.private_key:
            st.warning("🚫 Please generate keys in the 'Key Generation' section.")
        if not st.session_state.encrypted_text_msg:
            st.warning("🚫 Please encrypt a text message in the 'Text Encryption' section.")
        
        if st.session_state.private_key and not st.session_state.encrypted_text_msg:
            st.info("Once you encrypt a text message, it will automatically appear here for decryption.")

# --- Section 4: Image Encryption & Decryption ---
elif page == "4. Image Encryption & Decryption":
    st.header("4. Image Encryption & Decryption 🖼️")
    st.write("This section demonstrates a *simplified* byte-by-byte encryption/decryption of an image using RSA.")
    st.warning("⚠️ **Penting:** Mengenkripsi gambar besar secara langsung dengan RSA (terutama byte-per-byte seperti yang ditunjukkan di sini) sangat tidak efisien dan bukan cara RSA digunakan dalam skenario dunia nyata. RSA biasanya digunakan untuk mengenkripsi *kunci simetris*, yang kemudian mengenkripsi data besar yang sebenarnya (seperti gambar). Demo ini murni untuk pemahaman konseptual tentang operasi RSA pada angka yang berasal dari data biner.")

    st.subheader("Enkripsi Gambar")
    uploaded_file = st.file_uploader("Unggah gambar (misalnya, PNG, JPG)", type=["png", "jpg", "jpeg"])

    if uploaded_file is not None:
        # Read the file as bytes
        image_bytes = uploaded_file.read()
        st.session_state.original_image_bytes = image_bytes
        st.session_state.original_image_type = uploaded_file.type # Store MIME type
        
        st.info(f"Gambar diunggah: {uploaded_file.name} ({len(image_bytes)} bytes)")
        try:
            # Try to open the image with PIL to display it
            img_preview = Image.open(io.BytesIO(image_bytes))
            st.image(img_preview, caption="Pratinjau Gambar Asli.", use_column_width=True)
        except Exception as e:
            st.error(f"Tidak dapat mempratinjau gambar. Pastikan ini adalah file gambar yang valid. Error: {e}")
            st.session_state.original_image_bytes = None # Clear invalid image data
            st.session_state.original_image_type = None
            uploaded_file = None # Reset uploader to prevent re-processing

    if uploaded_file is not None and st.session_state.public_key:
        n_pub, e_pub = st.session_state.public_key
        st.info(f"Menggunakan Kunci Publik: `(n={n_pub}, e={e_pub})` untuk mengenkripsi gambar.")
        
        if st.button("Enkripsi Gambar", type="primary"):
            if not st.session_state.public_key:
                st.warning("🚫 Mohon hasilkan kunci di bagian 'Key Generation' terlebih dahulu.")
            else:
                with st.spinner("Mengenkripsi gambar... Ini mungkin memakan waktu untuk gambar yang lebih besar."):
                    encrypted_data_ints = encrypt_bytes(st.session_state.public_key, st.session_state.original_image_bytes)
                    if encrypted_data_ints:
                        st.session_state.encrypted_image_data = encrypted_data_ints
                        st.success("Gambar berhasil dienkripsi!")
                        st.write(f"**Data Gambar Terenkripsi (daftar {len(encrypted_data_ints)} integer):**")
                        # Displaying the entire list can be very long, so truncate for display
                        st.code(str(encrypted_data_ints[:50]) + "..." if len(encrypted_data_ints) > 50 else str(encrypted_data_ints))
                        st.info("Data gambar asli telah diubah menjadi urutan angka yang panjang ini.")
                    else:
                        st.error("Enkripsi gambar gagal. Periksa pesan di atas.")
    elif uploaded_file is None:
        st.info("Unggah file gambar (PNG, JPG) untuk memulai enkripsi gambar.")
    else: # Keys not generated
        st.warning("🚫 Mohon hasilkan kunci di bagian 'Key Generation' terlebih dahulu.")


    st.markdown("---")
    st.subheader("Dekripsi Gambar")
    if st.session_state.private_key and st.session_state.encrypted_image_data:
        n_priv, d_priv = st.session_state.private_key
        st.info(f"Menggunakan Kunci Pribadi: `(n={n_priv}, d={d_priv})` untuk mendekripsi gambar.")
        st.write(f"**Data Gambar Terenkripsi yang akan Didekripsi (beberapa integer pertama):**")
        st.code(str(st.session_state.encrypted_image_data[:50]) + "..." if len(st.session_state.encrypted_image_data) > 50 else str(st.session_state.encrypted_image_data))

        if st.button("Dekripsi Gambar", type="primary"):
            if not st.session_state.private_key:
                st.warning("🚫 Mohon hasilkan kunci terlebih dahulu.")
            elif not st.session_state.encrypted_image_data:
                st.warning("🚫 Tidak ada data gambar terenkripsi yang ditemukan. Mohon enkripsi gambar terlebih dahulu.")
            else:
                with st.spinner("Mendekripsi gambar... Ini mungkin memakan waktu."):
                    decrypted_image_bytes = decrypt_bytes(st.session_state.private_key, st.session_state.encrypted_image_data)
                    
                    if decrypted_image_bytes:
                        st.success("Gambar berhasil didekripsi!")
                        st.subheader("Pratinjau Gambar Terdekripsi:")
                        
                        # Use io.BytesIO to allow st.image to display bytes
                        image_io = io.BytesIO(decrypted_image_bytes)
                        try:
                            # Use the original MIME type for display
                            st.image(image_io, caption="Gambar Terdekripsi", use_column_width=True, format=st.session_state.original_image_type)
                            
                            st.markdown("---")
                            st.subheader("Verifikasi")
                            if st.session_state.original_image_bytes == decrypted_image_bytes:
                                st.success("🎉 Verifikasi: Dekripsi Berhasil! Byte gambar asli cocok dengan byte gambar yang didekripsi.")
                            else:
                                st.error("❌ Verifikasi: Dekripsi Gagal! Byte gambar asli TIDAK cocok dengan byte gambar yang didekripsi.")
                                st.write(f"Panjang byte asli: {len(st.session_state.original_image_bytes)}")
                                st.write(f"Panjang byte terdekripsi: {len(decrypted_image_bytes)}")
                        except Exception as e:
                            st.error(f"Tidak dapat menampilkan gambar yang didekripsi. Mungkin rusak atau bukan format gambar yang valid. Error: {e}")
                            st.write("Byte yang didekripsi (100 pertama):")
                            st.code(decrypted_image_bytes[:100])
                    else:
                        st.error("Dekripsi gambar gagal.")
    else:
        if not st.session_state.private_key:
            st.warning("🚫 Mohon hasilkan kunci di bagian 'Key Generation' terlebih dahulu.")
        if not st.session_state.encrypted_image_data:
            st.warning("🚫 Mohon enkripsi gambar di bagian 'Enkripsi Gambar' terlebih dahulu.")

st.sidebar.markdown("---")
st.sidebar.caption("💡 Tip: Jelajahi bagian-bagian menggunakan sidebar.")
st.markdown("---")
st.caption("Penafian: Ini adalah demonstrasi edukasi yang disederhanakan. "
           "Implementasi kriptografi dunia nyata menggunakan skema padding tingkat lanjut, "
           "ukuran kunci yang lebih besar, dan penanganan kesalahan yang kuat untuk keamanan dan keandalan yang ditingkatkan.")
