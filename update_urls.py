import os
import re

mapping = {
    "'login'": "'auth.login'",
    "'register'": "'auth.register'",
    "'logout'": "'auth.logout'",
    "'index'": "'main.index'",
    "'profile'": "'main.profile'",
    
    "'tickets'": "'tickets.index'",
    "'new_ticket'": "'tickets.new'",
    "'view_ticket'": "'tickets.view'",
    "'edit_ticket'": "'tickets.edit'",
    "'delete_ticket'": "'tickets.delete'",
    
    "'articles'": "'articles.index'",
    "'view_article'": "'articles.view'",
    "'new_article'": "'articles.new'",
    "'edit_article'": "'articles.edit'",
    "'delete_article'": "'articles.delete'",
    "'delete_article_image'": "'articles.delete_image'",
    
    "'todos'": "'todos.index'",
    "'new_todo'": "'todos.new'",
    "'toggle_todo'": "'todos.toggle'",
    "'delete_todo'": "'todos.delete'",
    "'view_todo'": "'todos.view'",
    "'edit_todo'": "'todos.edit'",
    
    "'admin_users'": "'admin.users'",
    "'admin_new_user'": "'admin.new_user'",
    "'admin_new_ad_user'": "'admin.new_ad_user'",
    "'admin_edit_user'": "'admin.edit_user'",
    "'admin_delete_user'": "'admin.delete_user'",
    "'admin_user_detail'": "'admin.user_detail'",
    
    "'categories'": "'admin.categories'",
    "'new_category'": "'admin.new_category'",
    "'edit_category'": "'admin.edit_category'",
    "'delete_category'": "'admin.delete_category'",
    
    "'statuses'": "'admin.statuses'",
    "'new_status'": "'admin.new_status'",
    "'edit_status'": "'admin.edit_status'",
    "'delete_status'": "'admin.delete_status'",
    
    "'ad_settings'": "'admin.ad_settings'",
    "'ad_test'": "'admin.ad_test'",
    "'ad_sync'": "'admin.ad_sync'"
}

def update_templates(templates_dir):
    for root, _, files in os.walk(templates_dir):
        for file in files:
            if file.endswith('.html'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                original = content
                for old_val, new_val in mapping.items():
                    # Replace url_for('old') to url_for('new')
                    # We ensure it replaces specific single quotes format
                    pattern = r"url_for\(" + old_val + r"([,\)])"
                    replacement = r"url_for(" + new_val + r"\1"
                    content = re.sub(pattern, replacement, content)

                if content != original:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)
                    print(f"Updated: {filepath}")

if __name__ == '__main__':
    update_templates(os.path.join(os.path.dirname(__file__), 'templates'))
