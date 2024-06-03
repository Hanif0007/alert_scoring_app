import streamlit as st
import json
import os

# Load password from secrets
ADMIN_PASSWORD = st.secrets["admin_password"]

# Define the default categories and weights as provided in the document
default_weights = {
    "base_weights": {
        "Critical": 50,
        "Non-Critical": 10
    },
    "category_weights": {
        "Desktop/Users": 10,
        "Servers/Cloud/Databases": 20,
        "Network": 20,
        "Environment/Physical": 20
    },
    "part2_weights": {
        "Legacy": 30,
        "CERT": 20,
        "Audit Report": 25,
        "Pen Test": 25
    },
    "part3_weights": {
        "Resource Development": 5,
        "Initial Access": 10,
        "Execution": 15,
        "Persistence": 15,
        "Privilege Escalation": 15,
        "Defense Evasion": 15,
        "Credential Access": 15,
        "Discovery": 15,
        "Lateral Movement": 15,
        "Collection": 15,
        "Command and Control": 15,
        "Exfiltration": 25,
        "Impact": 25
    },
    "part4_weights": {
        "No Controls": 40,
        "Weak Controls": 20
    }
}

# Load weights from file if it exists, otherwise use default
def load_weights():
    if os.path.exists("weights.json"):
        with open("weights.json", "r") as f:
            return json.load(f)
    else:
        return default_weights

weights = load_weights()

# Save weights to a file
def save_weights(weights):
    with open("weights.json", "w") as f:
        json.dump(weights, f)

# Function to calculate alert score based on user inputs
def calculate_alert_score(asset_type, asset_category, subcategories, mitre_categories, control_categories):
    base_weight = weights["base_weights"].get(asset_type, 0)
    category_weight = weights["category_weights"].get(asset_category, 0)

    subcategory_weight = sum(weights["part2_weights"].get(sub, 0) for sub in subcategories)
    subcategory_weight += sum(weights["part3_weights"].get(sub, 0) for sub in mitre_categories)
    subcategory_weight += sum(weights["part4_weights"].get(sub, 0) for sub in control_categories)

    alert_score = base_weight + category_weight + subcategory_weight
    return alert_score

# Function to handle the admin panel
def admin_panel():
    st.title("Admin Panel")

    st.subheader("Base Weights")
    for key in weights["base_weights"]:
        weights["base_weights"][key] = st.number_input(f"Base Weight - {key}", value=weights["base_weights"][key])

    st.subheader("Category Weights")
    for key in weights["category_weights"]:
        weights["category_weights"][key] = st.number_input(f"Category Weight - {key}", value=weights["category_weights"][key])

    st.subheader("Part 2 Weights")
    for key in weights["part2_weights"]:
        weights["part2_weights"][key] = st.number_input(f"Part 2 Weight - {key}", value=weights["part2_weights"][key])

    st.subheader("Part 3 Weights")
    for key in weights["part3_weights"]:
        weights["part3_weights"][key] = st.number_input(f"Part 3 Weight - {key}", value=weights["part3_weights"][key])

    st.subheader("Part 4 Weights")
    for key in weights["part4_weights"]:
        weights["part4_weights"][key] = st.number_input(f"Part 4 Weight - {key}", value=weights["part4_weights"][key])

    st.subheader("Manage Subcategories")

    if st.button("Add Subcategory to Part 2"):
        new_subcategory = st.text_input("Enter new subcategory for Part 2:")
        if new_subcategory:
            weights["part2_weights"][new_subcategory] = 0
            st.experimental_rerun()

    if st.button("Add Subcategory to Part 3"):
        new_subcategory = st.text_input("Enter new subcategory for Part 3:")
        if new_subcategory:
            weights["part3_weights"][new_subcategory] = 0
            st.experimental_rerun()

    if st.button("Add Subcategory to Part 4"):
        new_subcategory = st.text_input("Enter new subcategory for Part 4:")
        if new_subcategory:
            weights["part4_weights"][new_subcategory] = 0
            st.experimental_rerun()

    st.subheader("Delete Subcategory")
    subcategory_to_delete = st.selectbox("Select subcategory to delete", 
        list(weights["part2_weights"].keys()) + list(weights["part3_weights"].keys()) + list(weights["part4_weights"].keys()))
    if st.button("Delete Selected Subcategory"):
        if subcategory_to_delete in weights["part2_weights"]:
            del weights["part2_weights"][subcategory_to_delete]
        elif subcategory_to_delete in weights["part3_weights"]:
            del weights["part3_weights"][subcategory_to_delete]
        elif subcategory_to_delete in weights["part4_weights"]:
            del weights["part4_weights"][subcategory_to_delete]
        st.experimental_rerun()

    if st.button("Save Changes"):
        save_weights(weights)
        st.success("Weights saved successfully")
        st.session_state.admin_logged_in = False
        st.experimental_set_query_params()
        st.experimental_rerun()

# Main Streamlit App
st.title("Cyber Security Alert Scoring Model")

if "admin_logged_in" not in st.session_state:
    st.session_state.admin_logged_in = False

if st.session_state.admin_logged_in:
    admin_panel()
else:
    asset_type = st.selectbox('Asset Type:', ['Critical', 'Non-Critical'])
    asset_category = st.selectbox('Category:', ['Desktop/Users', 'Servers/Cloud/Databases', 'Network', 'Environment/Physical'])
    subcategories = st.multiselect('Subcategories:', list(weights["part2_weights"].keys()))
    mitre_type = st.selectbox('MITRE Type:', ['None', 'External MITRE', 'Cloud MITRE'])

    if mitre_type != 'None':
        mitre_categories = st.multiselect(f'{mitre_type} Categories:', list(weights["part3_weights"].keys()))
    else:
        mitre_categories = []

    control_categories = st.multiselect('Controls:', list(weights["part4_weights"].keys()))

    if st.button('Calculate Score'):
        score = calculate_alert_score(asset_type, asset_category, subcategories, mitre_categories, control_categories)
        st.write(f"The alert score is: {score}")

    admin_password = st.text_input("Admin Password", type="password")
    if st.button("Login as Admin"):
        if admin_password == ADMIN_PASSWORD:
            st.session_state.admin_logged_in = True
            st.experimental_rerun()
        else:
            st.error("Incorrect password")

# JavaScript to scroll to the top of the page
scroll_to_top = """
<script>
window.scrollTo(0, 0);
</script>
"""
st.markdown(scroll_to_top, unsafe_allow_html=True)
