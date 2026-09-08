import streamlit as st
import pandas as pd
import plotly.express as px
from wordcloud import WordCloud, STOPWORDS
import matplotlib.pyplot as plt
import sqlite3
import random
import smtplib
from email.mime.text import MIMEText

# ==========================================
# 1. DATABASE SETUP & MIGRATIONS
# ==========================================
DB_FILE = "barrie_issues.db"

# Barrie Ward Center Coordinates & Community Names
BARRIE_WARD_INFO = {
    "Ward 1": {"name": "Little Lake / Georgian College / Eastview North", "lat": 44.4110, "lon": -79.6640},
    "Ward 2": {"name": "Downtown Barrie / Kempenfelt Waterfront", "lat": 44.3894, "lon": -79.6880},
    "Ward 3": {"name": "Codrington / Eastview South", "lat": 44.4020, "lon": -79.6700},
    "Ward 4": {"name": "Sunnidale / Letitia Heights", "lat": 44.4000, "lon": -79.7150},
    "Ward 5": {"name": "City Centre / Anne St / Allandale North", "lat": 44.3780, "lon": -79.7020},
    "Ward 6": {"name": "Ardagh Bluffs / West Barrie", "lat": 44.3580, "lon": -79.7280},
    "Ward 7": {"name": "Holly / Southwest Barrie", "lat": 44.3390, "lon": -79.7120},
    "Ward 8": {"name": "Allandale / Minet's Point", "lat": 44.3680, "lon": -79.6750},
    "Ward 9": {"name": "Painswick / South East", "lat": 44.3480, "lon": -79.6600},
    "Ward 10": {"name": "Innishore / Hewitt's / South Waterfront", "lat": 44.3350, "lon": -79.6380}
}

def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Issues Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            details TEXT,
            ward TEXT NOT NULL,
            category TEXT NOT NULL,
            severity INTEGER NOT NULL,
            submitted_by TEXT NOT NULL,
            status TEXT DEFAULT 'active', -- active, pending_resolution, resolved
            resolution_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Upvotes Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS issue_upvotes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL,
            voter_email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(issue_id, voter_email)
        )
    ''')
    
    # Comments Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS issue_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL,
            author_email TEXT NOT NULL,
            comment_text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Resolution Votes Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS resolution_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issue_id INTEGER NOT NULL,
            voter_email TEXT NOT NULL,
            vote_type TEXT NOT NULL,
            voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(issue_id, voter_email)
        )
    ''')
    
    # Populate initial sample data if clean DB
    c.execute("SELECT COUNT(*) FROM issues")
    if c.fetchone()[0] == 0:
        sample_issues = [
            ("Bayfield St Potholes", "Major potholes near 400 ramps damaging car rims.", "Ward 1", "Roads & Traffic", 5, "resident1@barrie.ca", "active"),
            ("Kempenfelt Bay Beach Litter", "Overflowing bins near Centennial Park playground.", "Ward 2", "Parks & Waterfront", 3, "resident2@barrie.ca", "active"),
            ("Route 8 Bus Transit Delays", "Connecting evening GO bus consistently late 20+ mins.", "Ward 8", "Public Transit", 4, "resident3@barrie.ca", "active"),
            ("Mapleview Traffic Gridlock", "Signal timing at Bryne Drive causes endless backups.", "Ward 7", "Roads & Traffic", 4, "resident4@barrie.ca", "active"),
            ("School Sidewalk Snow Drift", "Sidewalks near St. Gabriel school unplowed.", "Ward 9", "Snow & Winter", 4, "resident5@barrie.ca", "active"),
            ("Dunlop St Lantern Fixed", "Streetlights replaced near Five Points.", "Ward 2", "Community Safety", 2, "resident6@barrie.ca", "resolved"),
        ]
        c.executemany('''
            INSERT INTO issues (title, details, ward, category, severity, submitted_by, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', sample_issues)
        
        # Add sample upvotes
        c.execute("INSERT OR IGNORE INTO issue_upvotes (issue_id, voter_email) VALUES (1, 'voter1@barrie.ca'), (1, 'voter2@barrie.ca'), (4, 'voter1@barrie.ca')")
        # Add sample comment
        c.execute("INSERT INTO issue_comments (issue_id, author_email, comment_text) VALUES (1, 'resident7@barrie.ca', 'Hit this yesterday, blew out my front passenger tire!')")
    
    conn.commit()
    conn.close()

init_db()

# Helper function to mask email for privacy in comments
def mask_email(email):
    try:
        user, domain = email.split('@')
        if len(user) <= 2:
            masked_user = user[0] + "*"
        else:
            masked_user = user[0] + "***" + user[-1]
        return f"{masked_user}@{domain}"
    except:
        return "resident@barrie.ca"

# ==========================================
# 2. EMAIL OTP AUTHENTICATION
# ==========================================
def send_otp_email(to_email, code):
    if "smtp" in st.secrets:
        try:
            smtp_conf = st.secrets["smtp"]
            msg = MIMEText(f"Your Barrie Civic Issue verification code is: {code}")
            msg['Subject'] = "Barrie Issue Tracker - Verification Code"
            msg['From'] = smtp_conf['sender_email']
            msg['To'] = to_email
            with smtplib.SMTP_SSL(smtp_conf['server'], smtp_conf['port']) as server:
                server.login(smtp_conf['username'], smtp_conf['password'])
                server.sendmail(smtp_conf['sender_email'], [to_email], msg.as_string())
            return True, "Code sent via email!"
        except Exception as e:
            return False, f"Email sending failed: {e}"
    else:
        return True, f"DEMO MODE CODE: **{code}**"

if "auth_email" not in st.session_state:
    st.session_state.auth_email = None
if "pending_otp" not in st.session_state:
    st.session_state.pending_otp = None
if "target_email" not in st.session_state:
    st.session_state.target_email = None
if "selected_word" not in st.session_state:
    st.session_state.selected_word = None

# ==========================================
# 3. SIDEBAR: AUTH & SUBMISSION
# ==========================================
st.set_page_config(page_title="Barrie Civic Issue Tracker", page_icon="🏙️", layout="wide")

st.sidebar.title("🏙️ BarriePulse")

# Auth Box
with st.sidebar.expander("👤 Email Verification", expanded=(st.session_state.auth_email is None)):
    if st.session_state.auth_email:
        st.success(f"Verified: **{st.session_state.auth_email}**")
        if st.button("Log Out"):
            st.session_state.auth_email = None
            st.session_state.pending_otp = None
            st.rerun()
    else:
        email_input = st.text_input("Enter your email:")
        if st.button("Get Verification Code"):
            if "@" in email_input and "." in email_input:
                code = str(random.randint(100000, 999999))
                st.session_state.pending_otp = code
                st.session_state.target_email = email_input.strip().lower()
                ok, msg = send_otp_email(st.session_state.target_email, code)
                if ok:
                    st.info(msg)
                else:
                    st.error(msg)
            else:
                st.error("Enter a valid email address.")

        if st.session_state.pending_otp:
            user_code = st.text_input("Enter 6-digit Code:", max_chars=6)
            if st.button("Verify Code"):
                if user_code.strip() == st.session_state.pending_otp:
                    st.session_state.auth_email = st.session_state.target_email
                    st.session_state.pending_otp = None
                    st.success("Verified successfully!")
                    st.rerun()
                else:
                    st.error("Invalid code.")

st.sidebar.divider()
st.sidebar.subheader("📢 Report a New Issue")

BARRIE_WARDS = [f"Ward {i}" for i in range(1, 11)]
CATEGORIES = [
    "Roads & Traffic", "Public Transit", "Parks & Waterfront", 
    "Housing & Social Services", "Snow & Winter", "Community Safety", "Other"
]

if st.session_state.auth_email:
    with st.sidebar.form("new_issue_form", clear_on_submit=True):
        new_title = st.text_input("Issue Headline (1-5 words):", placeholder="e.g., Mapleview Pothole")
        new_details = st.text_area("Details:", placeholder="Describe the issue and exact street/landmark...")
        new_ward = st.selectbox("Ward:", BARRIE_WARDS, format_func=lambda w: f"{w} ({BARRIE_WARD_INFO[w]['name']})")
        new_cat = st.selectbox("Category:", CATEGORIES)
        new_sev = st.slider("Severity (1 = Minor, 5 = Critical Hazard):", 1, 5, 3)
        
        if st.form_submit_button("Submit Issue"):
            if len(new_title.strip()) < 3:
                st.error("Please provide a title.")
            else:
                conn = get_db_connection()
                conn.execute('''
                    INSERT INTO issues (title, details, ward, category, severity, submitted_by, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'active')
                ''', (new_title.strip(), new_details.strip(), new_ward, new_cat, new_sev, st.session_state.auth_email))
                conn.commit()
                conn.close()
                st.success("Issue submitted!")
                st.rerun()
else:
    st.sidebar.info("👉 Verify your email above to report issues, upvote, or comment.")

# ==========================================
# 4. MAIN PAGE: WORD CLOUD & INTERACTIVITY
# ==========================================
st.title("🏙️ City of Barrie Community Issue Tracker")
st.caption("A resident-powered radar for tracking municipal issues, upvoting priorities, and confirming civic fixes.")

col_view, col_sort = st.columns([2, 1])
with col_view:
    view_filter = st.radio("View Status:", ["Active Issues", "Civic Wins (Resolved)"], horizontal=True)
with col_sort:
    sort_option = st.selectbox("Sort Issues By:", ["Most Upvoted", "Highest Severity", "Newest"])

# Fetch Issues with Upvote Count
conn = get_db_connection()
status_val = "resolved" if view_filter == "Civic Wins (Resolved)" else "active', 'pending_resolution"
query = f'''
    SELECT i.*, 
           (SELECT COUNT(*) FROM issue_upvotes WHERE issue_id = i.id) as upvotes,
           (SELECT COUNT(*) FROM issue_comments WHERE issue_id = i.id) as comment_count
    FROM issues i
    WHERE status IN ('{status_val}')
'''
df_issues = pd.read_sql_query(query, conn)
conn.close()

# Keyword filter handler
if st.session_state.selected_word:
    st.info(f"🔍 Filtering by keyword: **{st.session_state.selected_word}**")
    if st.button("✖ Clear Keyword Filter"):
        st.session_state.selected_word = None
        st.rerun()
    df_issues = df_issues[df_issues['title'].str.contains(st.session_state.selected_word, case=False, na=False) |
                          df_issues['details'].str.contains(st.session_state.selected_word, case=False, na=False)]

# Sorting logic
if sort_option == "Most Upvoted":
    df_issues = df_issues.sort_values(by="upvotes", ascending=False)
elif sort_option == "Highest Severity":
    df_issues = df_issues.sort_values(by="severity", ascending=False)
else:
    df_issues = df_issues.sort_values(by="created_at", ascending=False)

# SECTION A: INTERACTIVE WORD CLOUD
st.subheader("☁️ Issue Word Cloud")
if not df_issues.empty:
    all_titles = " ".join(df_issues['title'].tolist())
    custom_stopwords = set(STOPWORDS).union({"barrie", "city", "street", "road", "ave", "avenue", "st", "problem", "issue"})
    
    wc = WordCloud(
        width=1000, height=320, 
        background_color="white", 
        colormap="viridis" if view_filter == "Active Issues" else "summer",
        stopwords=custom_stopwords, collocations=False
    ).generate(all_titles)
    
    fig_wc, ax = plt.subplots(figsize=(10, 3.2))
    ax.imshow(wc, interpolation="bilinear")
    ax.axis("off")
    st.pyplot(fig_wc)

    # Clickable Word Chips to Filter Issues
    st.write("**Click a trending keyword below to filter the dashboard:**")
    word_freq = wc.words_
    top_keywords = list(word_freq.keys())[:12]
    
    chip_cols = st.columns(len(top_keywords) if len(top_keywords) <= 6 else 6)
    for idx, word in enumerate(top_keywords[:12]):
        col_idx = idx % 6
        if chip_cols[col_idx].button(f"#{word}", key=f"chip_{word}"):
            st.session_state.selected_word = word
            st.rerun()
else:
    st.info("No issues found.")

# ==========================================
# 5. BARRIE WARD & COMMUNITY MAP
# ==========================================
st.divider()
st.subheader("🗺️ Barrie Ward & Community Map")

# Prepare Ward Aggregates for Map
map_rows = []
for ward, info in BARRIE_WARD_INFO.items():
    ward_issues = df_issues[df_issues['ward'] == ward]
    count = len(ward_issues)
    map_rows.append({
        "Ward": ward,
        "Community": info["name"],
        "lat": info["lat"],
        "lon": info["lon"],
        "Issue Count": count,
        "Marker Size": max(count * 6, 12)  # Ensure markers remain visible even if 0 count
    })

df_map = pd.DataFrame(map_rows)

fig_map = px.scatter_mapbox(
    df_map,
    lat="lat",
    lon="lon",
    size="Marker Size",
    color="Issue Count",
    hover_name="Ward",
    hover_data={"Community": True, "Issue Count": True, "lat": False, "lon": False, "Marker Size": False},
    color_continuous_scale="Reds" if view_filter == "Active Issues" else "Greens",
    zoom=11.2,
    center={"lat": 44.378, "lon": -79.680},
    mapbox_style="open-street-map",
    height=450
)
fig_map.update_layout(margin={"r": 0, "t": 0, "l": 0, "b": 0})
st.plotly_chart(fig_map, use_container_width=True)

# Supplementary Ward & Category Charts
col_w, col_c = st.columns(2)
with col_w:
    ward_counts = df_issues['ward'].value_counts().reset_index()
    ward_counts.columns = ['Ward', 'Count']
    st.plotly_chart(px.bar(ward_counts, x='Ward', y='Count', title="Issues by Ward", color='Count', color_continuous_scale='Blues'), use_container_width=True)
with col_c:
    cat_counts = df_issues['category'].value_counts().reset_index()
    cat_counts.columns = ['Category', 'Count']
    st.plotly_chart(px.pie(cat_counts, values='Count', names='Category', title="Issues by Category", hole=0.4), use_container_width=True)

# ==========================================
# 6. ISSUE FEED: UPVOTING, COMMENTS & RESOLUTIONS
# ==========================================
st.divider()
st.subheader("📋 Community Issue Feed")

if df_issues.empty:
    st.info("No matching issues found.")
else:
    for _, issue in df_issues.iterrows():
        issue_id = issue['id']
        community_name = BARRIE_WARD_INFO.get(issue['ward'], {}).get('name', '')
        
        with st.container(border=True):
            header_col, upvote_col = st.columns([5, 1])
            
            with header_col:
                st.markdown(f"### {issue['title']}")
                st.caption(f"📍 **{issue['ward']}** ({community_name}) &nbsp;|&nbsp; 🏷️ **{issue['category']}** &nbsp;|&nbsp; ⚠️ Severity: **{issue['severity']}/5**")
                if issue['details']:
                    st.write(issue['details'])
            
            with upvote_col:
                # Check if current user already upvoted
                has_upvoted = False
                if st.session_state.auth_email:
                    conn = get_db_connection()
                    check = conn.execute("SELECT id FROM issue_upvotes WHERE issue_id = ? AND voter_email = ?", (issue_id, st.session_state.auth_email)).fetchone()
                    conn.close()
                    has_upvoted = check is not None
                
                upvote_label = f"▲ Upvoted ({issue['upvotes']})" if has_upvoted else f"▲ Upvote ({issue['upvotes']})"
                if st.button(upvote_label, key=f"upvote_{issue_id}", disabled=(not st.session_state.auth_email or has_upvoted)):
                    conn = get_db_connection()
                    conn.execute("INSERT OR IGNORE INTO issue_upvotes (issue_id, voter_email) VALUES (?, ?)", (issue_id, st.session_state.auth_email))
                    conn.commit()
                    conn.close()
                    st.rerun()

            # Expandable Comments Section
            with st.expander(f"💬 Comments & Updates ({issue['comment_count']})"):
                conn = get_db_connection()
                comments = conn.execute("SELECT * FROM issue_comments WHERE issue_id = ? ORDER BY created_at ASC", (issue_id,)).fetchall()
                conn.close()
                
                if comments:
                    for comm in comments:
                        st.markdown(f"**{mask_email(comm['author_email'])}** *({comm['created_at'][:16]})*")
                        st.write(comm['comment_text'])
                        st.markdown("---")
                else:
                    st.caption("No comments yet. Be the first to share an update.")
                
                # New comment form
                if st.session_state.auth_email:
                    with st.form(key=f"comm_form_{issue_id}", clear_on_submit=True):
                        c_text = st.text_input("Add a comment / update:")
                        if st.form_submit_button("Post Comment"):
                            if len(c_text.strip()) > 1:
                                conn = get_db_connection()
                                conn.execute("INSERT INTO issue_comments (issue_id, author_email, comment_text) VALUES (?, ?, ?)",
                                             (issue_id, st.session_state.auth_email, c_text.strip()))
                                conn.commit()
                                conn.close()
                                st.rerun()
                else:
                    st.caption("🔒 Verify your email in the sidebar to leave a comment.")

            # Anti-Sabotage Resolution Workflow
            conn = get_db_connection()
            votes_df = pd.read_sql_query("SELECT vote_type, COUNT(*) as count FROM resolution_votes WHERE issue_id = ? GROUP BY vote_type", conn, params=(issue_id,))
            conn.close()
            
            fixed_votes = votes_df[votes_df['vote_type'] == 'fixed']['count'].sum() if not votes_df.empty else 0
            still_votes = votes_df[votes_df['vote_type'] == 'still_an_issue']['count'].sum() if not votes_df.empty else 0
            
            if issue['status'] == 'pending_resolution':
                st.warning(f"🟡 **Pending Resolution**: Proposed reason: *\"{issue['resolution_reason']}\"*")
                st.write(f"Consensus Check: **{fixed_votes} Fixed** vs **{still_votes} Still an Issue** *(Net +3 needed to resolve)*")
                
                if st.session_state.auth_email:
                    b1, b2, _ = st.columns([1, 1, 3])
                    with b1:
                        if st.button("🟢 Fixed", key=f"fix_{issue_id}"):
                            conn = get_db_connection()
                            conn.execute("INSERT OR REPLACE INTO resolution_votes (issue_id, voter_email, vote_type) VALUES (?, ?, 'fixed')", (issue_id, st.session_state.auth_email))
                            conn.commit()
                            cur = pd.read_sql_query("SELECT vote_type FROM resolution_votes WHERE issue_id = ?", conn, params=(issue_id,))
                            if (cur['vote_type'] == 'fixed').sum() - (cur['vote_type'] == 'still_an_issue').sum() >= 3:
                                conn.execute("UPDATE issues SET status = 'resolved' WHERE id = ?", (issue_id,))
                                conn.commit()
                            conn.close()
                            st.rerun()
                    with b2:
                        if st.button("🔴 Still an Issue", key=f"still_{issue_id}"):
                            conn = get_db_connection()
                            conn.execute("INSERT OR REPLACE INTO resolution_votes (issue_id, voter_email, vote_type) VALUES (?, ?, 'still_an_issue')", (issue_id, st.session_state.auth_email))
                            conn.commit()
                            cur = pd.read_sql_query("SELECT vote_type FROM resolution_votes WHERE issue_id = ?", conn, params=(issue_id,))
                            if (cur['vote_type'] == 'still_an_issue').sum() >= (cur['vote_type'] == 'fixed').sum():
                                conn.execute("UPDATE issues SET status = 'active', resolution_reason = NULL WHERE id = ?", (issue_id,))
                                conn.commit()
                            conn.close()
                            st.rerun()
            elif issue['status'] == 'active' and st.session_state.auth_email:
                with st.popover("Propose as Resolved"):
                    reason = st.text_input("How was this fixed?", key=f"res_{issue_id}", placeholder="e.g. City repaved this lane yesterday")
                    if st.button("Submit Fix Proposal", key=f"btn_res_{issue_id}"):
                        if len(reason.strip()) > 5:
                            conn = get_db_connection()
                            conn.execute("UPDATE issues SET status = 'pending_resolution', resolution_reason = ? WHERE id = ?", (reason.strip(), issue_id))
                            conn.execute("INSERT OR REPLACE INTO resolution_votes (issue_id, voter_email, vote_type) VALUES (?, ?, 'fixed')", (issue_id, st.session_state.auth_email))
                            conn.commit()
                            conn.close()
                            st.rerun()

# Civic Footer
st.divider()
st.markdown("""
**🏛️ City of Barrie Direct Services:**
- Need urgent assistance? Submit official requests to [Service Barrie 311](https://www.barrie.ca/city-hall/service-barrie).
- Speak with your local representative via the [Barrie Ward Councillor Directory](https://www.barrie.ca/city-hall/city-council).
""")
