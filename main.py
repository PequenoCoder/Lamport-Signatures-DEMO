import matplotlib.pyplot as plt
import matplotlib.patches as patches
import textwrap
from cryptography.fernet import Fernet
import secrets
import hashlib
from matplotlib.widgets import TextBox

# ------------------------------------------------------------------------
#                      Global Matplotlib/Slide Variables
# ------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(15, 6))

slide_index = 0          # Tracks which bubble (slide) is currently displayed
user_message = None      # Will store the user's input once
intro_shown = False      # Indicates if the intro slide was shown

# Variables holding cryptographic objects/data
private_key = None
public_key = None
encryption_key = None
signature = None
encrypted_message = None
decrypted_message = None

# For diagram displays
inset_ax = None
message_text_box = None

# The sequential steps for slides
steps = [
    {"label": "Generate Lamport Keys\n(Private & Public)", "pos": (0, 2)},
    {"label": "Input Message", "pos": (5, 2)},
    {"label": "Encrypt Message\n(Fernet Encryption)", "pos": (10, 2)},
    {"label": "Sign Encrypted Message\n(Lamport Signature)", "pos": (15, 2)},
    {"label": "Send Encrypted Message,\nSignature, & Key", "pos": (20, 2)},
    {"label": "Verify Signature\n(Lamport Verification)", "pos": (25, 2)},
    {"label": "Decrypt & Display Message", "pos": (30, 2)},
]


# ------------------------------------------------------------------------
#                       Lamport Key Pair Functions
# ------------------------------------------------------------------------
def generate_lamport_keys():
    """
    Generates a Lamport key pair (private_key, public_key).

    Each private key consists of 256 pairs of random 32-byte values.
    Each public key is the SHA-256 hash of each corresponding private key value.
    """
    private_key = []
    public_key = []

    for _ in range(256):
        sk0 = secrets.token_bytes(32)  # random secret key 0
        sk1 = secrets.token_bytes(32)  # random secret key 1
        pk0 = hashlib.sha256(sk0).digest()  # hash of sk0
        pk1 = hashlib.sha256(sk1).digest()  # hash of sk1
        private_key.append((sk0, sk1))
        public_key.append((pk0, pk1))

    return private_key, public_key


def lamport_sign(private_key, message):
    """
    Creates a Lamport signature for 'message' given a 'private_key'.
    - message: a bytes object
    - private_key: list of 256 pairs
    """
    hash_msg = hashlib.sha256(message).digest()
    hash_bits = bin(int.from_bytes(hash_msg, byteorder='big'))[2:].zfill(256)

    signature = []
    for i, bit in enumerate(hash_bits):
        # If bit is '0', use the first element from the i-th pair
        # If bit is '1', use the second element
        signature.append(private_key[i][0] if bit == '0' else private_key[i][1])

    return signature


def lamport_verify(public_key, message, signature):
    """
    Verifies a Lamport signature for 'message' given a 'public_key' and 'signature'.
    - public_key: list of 256 (hash(sk0), hash(sk1)) pairs
    - message: bytes object
    - signature: list of 256 chosen private-key elements
    """
    hash_msg = hashlib.sha256(message).digest()
    hash_bits = bin(int.from_bytes(hash_msg, byteorder='big'))[2:].zfill(256)

    for i, bit in enumerate(hash_bits):
        sig_hash = hashlib.sha256(signature[i]).digest()

        if bit == '0':
            # If bit was '0', public_key[i][0] must match the hash of signature[i]
            if sig_hash != public_key[i][0]:
                return False
        else:
            # If bit was '1', public_key[i][1] must match the hash of signature[i]
            if sig_hash != public_key[i][1]:
                return False

    return True


# ------------------------------------------------------------------------
#                       Fernet Encryption/Decryption
# ------------------------------------------------------------------------
def encrypt_message(plain_text, key):
    """Encrypts plain_text (bytes) using the provided Fernet key."""
    f = Fernet(key)
    return f.encrypt(plain_text)


def decrypt_message(cipher_text, key):
    """Decrypts cipher_text (bytes) using the provided Fernet key."""
    f = Fernet(key)
    return f.decrypt(cipher_text)


# ------------------------------------------------------------------------
#                          Diagram-Related Drawing
# ------------------------------------------------------------------------
def create_lamport_diagram(ax):
    """
    Draws the main Lamport Signature Process Flow diagram on axes 'ax',
    with slightly smaller boxes, bigger text, and centered positioning.
    """
    box_width = 4
    box_height = 1.5

    for step in steps:
        x, y = step["pos"]
        wrapped_label = "\n".join(textwrap.wrap(step["label"], width=12))

        rect = patches.FancyBboxPatch(
            (x, y), box_width, box_height,
            boxstyle="round,pad=0.3",
            fc="lightblue",
            ec="black",
            lw=1.5
        )
        ax.add_patch(rect)

        ax.text(
            x + box_width / 2,
            y + box_height / 2,
            wrapped_label,
            ha="center",
            va="center",
            fontsize=12 
        )

    # Draw arrows between consecutive steps
    for i in range(len(steps) - 1):
        start_x = steps[i]["pos"][0] + box_width
        start_y = steps[i]["pos"][1] + box_height / 2
        end_x = steps[i+1]["pos"][0]
        end_y = steps[i+1]["pos"][1] + box_height / 2
        ax.annotate("",
                    xy=(end_x, end_y),
                    xytext=(start_x, start_y),
                    arrowprops=dict(arrowstyle="->", lw=2))

    ax.set_xlim(-2, 36)  # extra space on each side
    ax.set_ylim(0, 6)    # keep some margin top & bottom

    ax.axis("off")

    add_title(ax, "Lamport Signature Process Flow", 18)

def add_title(ax, title, fontsize):
    """
    Adds a title with a dark blue background box to the given Axes 'ax'.
    """
    ax.text(
        0.5, 0.95, title,
        transform=ax.transAxes,
        fontsize=fontsize,
        ha='center', va='center',
        color='white',
        bbox=dict(boxstyle="round,pad=0.6", fc='#003366', alpha=0.8, edgecolor='#003366')
    )


def format_signature(sig, max_elements=4):
    """Formats the signature array for printing (truncating to first 'max_elements')."""
    lines = []
    for i, s in enumerate(sig[:max_elements]):
        lines.append(f"Element {i}: {s.hex()[:8]}...")
    if len(sig) > max_elements:
        lines.append("...")
    return "".join(lines)


def format_keys(key_pairs, max_pairs=3):
    """
    Formats a list of key pairs into a readable string.
    Only shows the first 'max_pairs' pairs, each key truncated to 8 hex characters.
    """
    lines = []
    for i, pair in enumerate(key_pairs[:max_pairs]):
        key1 = pair[0].hex()[:8]
        key2 = pair[1].hex()[:8]
        lines.append(f"Pair {i}: ({key1}..., {key2}...)")
    if len(key_pairs) > max_pairs:
        lines.append("...")
    return "\n".join(lines)


def draw_signature_diagram(inset_ax, user_message, private_key, public_key, signature):
    """
    Draws a simplified signature diagram in 'inset_ax'. It references 'encrypted_message'
    for hashing (since we are signing the ciphertext).
    """
    # 1) Hash the ciphertext to get the bits
    hash_val = hashlib.sha256(encrypted_message).hexdigest()
    hash_bin = bin(int(hash_val, 16))[2:].zfill(256)

    # 2) Extract the first two pairs from the real private_key/public_key
    sk0_0, sk0_1 = private_key[0]  # Pair 0
    sk1_0, sk1_1 = private_key[1]  # Pair 1
    pk0_0, pk0_1 = public_key[0]   # Pair 0
    pk1_0, pk1_1 = public_key[1]   # Pair 1

    # 3) The real signature’s first two elements:
    sig_elem0 = signature[0]
    sig_elem1 = signature[1]

    # 4) Convert everything to truncated hex
    sk0_0_hex = sk0_0.hex()[:8]
    sk0_1_hex = sk0_1.hex()[:8]
    sk1_0_hex = sk1_0.hex()[:8]
    sk1_1_hex = sk1_1.hex()[:8]

    pk0_0_hex = pk0_0.hex()[:8]
    pk0_1_hex = pk0_1.hex()[:8]
    pk1_0_hex = pk1_0.hex()[:8]
    pk1_1_hex = pk1_1.hex()[:8]

    sig0_hex = sig_elem0.hex()[:8]
    sig1_hex = sig_elem1.hex()[:8]

    # -- Diagram Setup --
    inset_ax.set_xlim(0, 15)
    inset_ax.set_ylim(0, 10)
    inset_ax.axis("off")

    # Message box
    msg_box = patches.FancyBboxPatch((6.2, 5.5), 3, 1.5,
                                     boxstyle="round,pad=0.2",
                                     fc="lavender", ec="black", lw=2)
    inset_ax.add_patch(msg_box)
    inset_ax.text(
        7.7, 6.25,
        f"Message: {user_message.decode('utf-8')}\nHash (first 2 bits): {hash_bin[:2]}",
        ha="center", va="center", fontsize=10, fontweight="bold"
    )

    # Private Key Box
    priv_x, priv_y = 8.2, 3.25
    priv_width, priv_height = 3, 1.5
    priv_box = patches.FancyBboxPatch(
        (priv_x, priv_y), priv_width, priv_height,
        boxstyle="round,pad=0.2", fc="lightblue", ec="black", lw=2
    )
    inset_ax.add_patch(priv_box)
    inset_ax.text(9.65, 4.7, "Private Key Pair 0", ha="center", va="center", fontsize=10, fontweight="bold")
    inset_ax.text(9.65, 4.4, f"sk0: {sk0_0_hex}...", ha="center", va="center", fontsize=9)
    inset_ax.text(9.65, 4.2, f"sk1:  {sk0_1_hex}...", ha="center", va="center", fontsize=9)
    inset_ax.text(9.65, 3.8, "Private Key Pair 1", ha="center", va="center", fontsize=10, fontweight="bold")
    inset_ax.text(9.65, 3.5, f"sk0: {sk1_0_hex}...", ha="center", va="center", fontsize=9)
    inset_ax.text(9.65, 3.3, f"sk1: {sk1_1_hex}...", ha="center", va="center", fontsize=9)

    # Public Key Box
    pub_x, pub_y = 4.2, 3.25
    pub_width, pub_height = 3, 1.5
    pub_box = patches.FancyBboxPatch(
        (pub_x, pub_y), pub_width, pub_height,
        boxstyle="round,pad=0.2", fc="lightgreen", ec="black", lw=2
    )
    inset_ax.add_patch(pub_box)
    inset_ax.text(5.6, 4.7, "Public Key Pair 0", ha="center", va="center", fontsize=10, fontweight="bold")
    inset_ax.text(5.6, 4.4, f"hash(sk0): {pk0_0_hex}...", ha="center", va="center", fontsize=9)
    inset_ax.text(5.6, 4.2, f"hash(sk1): {pk0_1_hex}...", ha="center", va="center", fontsize=9)
    inset_ax.text(5.6, 3.8, "Public Key Pair 1", ha="center", va="center", fontsize=10, fontweight="bold")
    inset_ax.text(5.6, 3.5, f"hash(sk0): {pk1_0_hex}", ha="center", va="center", fontsize=9)
    inset_ax.text(5.6, 3.3, f"hash(sk1): {pk1_1_hex}", ha="center", va="center", fontsize=9)

    # Arrow connecting public/private boxes
    public_right_edge = (pub_x + pub_width, pub_y + pub_height/2)
    private_left_edge = (priv_x, priv_y + priv_height/2)
    inset_ax.annotate(
        "", xy=private_left_edge, xytext=public_right_edge,
        arrowprops=dict(arrowstyle="<-", lw=2)
    )

    # Signature Box
    sig_x, sig_y = 6.2, 1
    sig_width, sig_height = 3, 1
    sig_box = patches.FancyBboxPatch(
        (sig_x, sig_y), sig_width, sig_height,
        boxstyle="round,pad=0.2", fc="lightcoral", ec="black", lw=2
    )
    inset_ax.add_patch(sig_box)
    inset_ax.text(
        7.70, 1.75,
        f"\nSignature (first 2 elements):\n{{ {sig0_hex}, {sig1_hex} }}\n",
        ha="center", va="center", fontsize=10, fontweight="bold"
    )

    # Caption for bits
    inset_ax.text(
        7.5, 0.5,
        f"Lamport Signature (first 2): {sig_elem0.hex()}..., {sig_elem1.hex()}...",
        ha="center", va="center", fontsize=9
    )

    # Arrow from bottom-left of Private Key box to top-center of Signature box
    private_bottom_left = (priv_x, priv_y)
    signature_top_center = (sig_x + sig_width / 2, sig_y + sig_height)
    inset_ax.annotate(
        "", xy=signature_top_center, xytext=private_bottom_left,
        arrowprops=dict(arrowstyle="->", lw=2)
    )


# ------------------------------------------------------------------------
#                      TextBox for User Input
# ------------------------------------------------------------------------
def on_submit_user_message(txt):
    """
    Callback invoked when user presses Enter in the TextBox.
    Stores the user's input in 'user_message'.
    """
    global user_message
    user_message = txt.encode('utf-8')
    print("User message captured:", txt)


def show_message_text_box():
    """
    Creates a TextBox for message input at the bottom of the figure (if not already present).
    """
    global message_text_box
    if message_text_box is not None:
        return

    axbox = plt.axes([0.25, 0.07, 0.5, 0.05])  # left, bottom, width, height
    message_text_box = TextBox(axbox, 'Message: ', textalignment="left")
    message_text_box.on_submit(on_submit_user_message)


# ------------------------------------------------------------------------
#                           Intro Slide
# ------------------------------------------------------------------------
def show_intro(ax, name, project_title):
    """
    Displays an introductory slide with a big title, your name, and instructions.
    """
    ax.clear()
    ax.axis("off")

    # Main Title
    ax.text(
        0.5, 0.7,
        project_title,
        color='white',
        fontsize=30,
        ha='center', va='center',
        bbox=dict(boxstyle="round,pad=1", fc='navy', ec='white', lw=2)
    )

    # Name
    ax.text(
        0.5, 0.5,
        f"By: {name}",
        color='white',
        fontsize=20,
        ha='center', va='center',
        bbox=dict(boxstyle="round,pad=1", fc='purple', ec='white', lw=2)
    )

    # Footer note
    ax.text(
        0.5, 0.3,
        "Press the Right Arrow Key to Begin",
        color='yellow',
        fontsize=14,
        ha='center', va='center',
        bbox=dict(boxstyle="round,pad=0.5", fc='black', ec='yellow', lw=2)
    )

    fig.canvas.draw()


# ------------------------------------------------------------------------
#                      Event Handler for Navigation
# ------------------------------------------------------------------------
def on_key_press(event):
    """
    Event handler for right arrow key:
      1) Shows intro slide if not shown yet.
      2) Cycles through each step in 'steps'.
      3) Finally shows 'THANK YOU' once steps are exhausted.

    Pressing right arrow:
      - Clears main axes,
      - Possibly sets up or removes the text box,
      - Draws each step's bubble notes,
      - Optionally shows an inset diagram.
    """
    global intro_shown, slide_index, user_message
    global encryption_key, encrypted_message, signature
    global private_key, public_key, decrypted_message, inset_ax
    global message_text_box

    if event.key == 'right':
        # --- If intro not shown, show the main diagram on first press. ---
        if not intro_shown:
            intro_shown = True
            ax.clear()
            create_lamport_diagram(ax)
            fig.canvas.draw()
            return

        # Clear main axes for next step
        ax.clear()
        if inset_ax is not None:
            try:
                inset_ax.remove()
            except Exception as e:
                print("Error removing inset:", e)
            inset_ax = None

        # --- Slide progression ---
        if slide_index < len(steps):
            bubble_label = steps[slide_index]['label']

            if "Generate Lamport Keys" in bubble_label:
                # Generate new keys
                private_key, public_key = generate_lamport_keys()
                formatted_private = format_keys(private_key)
                formatted_public = format_keys(public_key)
                bubble_notes = (
                    "256 key pairs generated.\n\n"
                    "Private Keys (truncated):\n" + formatted_private + "\n\n" +
                    "Public Keys (truncated):\n" + formatted_public + "\n\n"
                    "Keys are single-use."
                )

            elif "Input Message" in bubble_label:
                # Show TextBox to let user type
                show_message_text_box()
                bubble_notes = (
                    "Type your message in the box below.\n"
                    "Press Enter in the text box to confirm.\n"
                    "Then press Right Arrow to continue."
                )

            elif "Encrypt Message" in bubble_label:
                # Remove TextBox if present
                if message_text_box is not None:
                    message_text_box.ax.remove()
                    message_text_box = None

                # Default if user typed nothing
                if user_message is None:
                    user_message = b"(No user input...)"

                encryption_key = Fernet.generate_key()
                encrypted_message = encrypt_message(user_message, encryption_key)
                bubble_notes = (
                    f"User input: {user_message.decode('utf-8')}\n"
                    "   ↓\n"
                    "Encrypted with Fernet:\n\n"
                    f"Key: {encryption_key.decode('utf-8')}\n"
                    f"\nEncrypted (truncated): {encrypted_message.decode('utf-8')[:60]}..."
                )

            elif "Sign Encrypted Message" in bubble_label:
                # Sign the ciphertext
                signature = lamport_sign(private_key, encrypted_message)
                bubble_notes = None

                # Show inset diagram
                inset_ax = fig.add_axes([0, 0, 1, 1])
                draw_signature_diagram(inset_ax, user_message, private_key, public_key, signature)

            elif "Send Encrypted Message" in bubble_label:
                bubble_notes = (
                    "Transmission includes:\n"
                    " • Encrypted Message\n"
                    " • Lamport Signature\n"
                    " • Encryption Key\n\n"
                    "Together, these guarantee confidentiality and verify authenticity."
                )

            elif "Verify Signature" in bubble_label:
                valid = lamport_verify(public_key, encrypted_message, signature)
                bubble_notes = "Signature verification: " + ("Valid" if valid else "Invalid") + "\n"
                bubble_notes += "Receiver re-hashes and compares with public key values."

            elif "Decrypt & Display Message" in bubble_label:
                # Decrypt and display in the same step
                decrypted_msg = decrypt_message(encrypted_message, encryption_key)
                bubble_notes = (
                    "Message decrypted with the Fernet key.\n"
                    "Original content restored.\n\n"
                    f"Final message:\n{decrypted_msg.decode('utf-8')}"
                )

            # Show the bubble_label as the title
            add_title(ax, bubble_label, 16)
            ax.axis("off")

            # Put bubble_notes text in a nice box
            if bubble_notes:
                ax.text(
                    0.5, 0.5,
                    bubble_notes,
                    transform=ax.transAxes,
                    fontsize=12,
                    ha='center', va='center',
                    bbox=dict(boxstyle="round,pad=0.6", fc="lightblue", ec="black", lw=1.5)
                )

            # Move to the next slide
            slide_index += 1

        else:
            # Past the last slide => show "THANK YOU" + optional QR code
            ax.clear()
            add_title(ax, "THANK YOU", 25)
            ax.axis("off")

            # Optionally load an image if you have one
            qr_img = plt.imread("QRCode.png")
            ax.imshow(qr_img, aspect='equal', extent=(15, 25, 1, 11))

        fig.canvas.draw()


# ------------------------------------------------------------------------
#                                  MAIN
# ------------------------------------------------------------------------
def main():
    """
    Entry point:
      - Show intro slide
      - Connect arrow key to on_key_press
      - Launch the Matplotlib event loop
    """
    show_intro(ax, name="Landon Coonrod", project_title="Lamport Signature")
    fig.canvas.mpl_connect('key_press_event', on_key_press)
    plt.show()


if __name__ == "__main__":
    main()
