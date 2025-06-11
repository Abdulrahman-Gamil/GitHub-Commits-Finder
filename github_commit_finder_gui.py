import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
import time
import os
from itertools import product
import queue
from threading import Thread
import urllib3
import re

urllib3.disable_warnings()

class GitHubCommitFinderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("GitHub Commit Finder")
        self.root.geometry("1000x700") 
        
        self.commit_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.running = False
        self.commits = []  
        
       
        self.root.configure(bg="#2b2b2b")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="#ffffff")
        style.configure("TEntry", fieldbackground="#3c3c3c", foreground="#ffffff")
        style.configure("TButton", background="#3c3c3c", foreground="#ffffff")
        style.configure("TRadiobutton", background="#2b2b2b", foreground="#ffffff")
        style.map("TButton", background=[("active", "#4a4a4a")])
        style.map("TRadiobutton", background=[("active", "#2b2b2b")])
        
        self.create_widgets()
        
    def create_widgets(self):
        
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.configure(style="TFrame")
        
        
        ttk.Label(main_frame, text="GitHub Token:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.token_entry = ttk.Entry(main_frame, width=60)
        self.token_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        
     
        ttk.Label(main_frame, text="Target Type:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.target_type = tk.StringVar(value="repository")
        ttk.Radiobutton(main_frame, text="Repository", variable=self.target_type, 
                       value="repository").grid(row=1, column=1, sticky=tk.W)
        ttk.Radiobutton(main_frame, text="Organization", variable=self.target_type, 
                       value="organization").grid(row=1, column=2, sticky=tk.W)
        
       
        ttk.Label(main_frame, text="Target URL/Name:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.target_entry = ttk.Entry(main_frame, width=60)
        self.target_entry.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        
     
        ttk.Label(main_frame, text="Organization List File:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.file_entry = ttk.Entry(main_frame, width=50)
        self.file_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=2)
        ttk.Button(main_frame, text="Browse", command=self.browse_file).grid(row=3, column=2, sticky=tk.W)
        
  
        ttk.Label(main_frame, text="Thread Count:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.thread_count = tk.StringVar(value="2")
        ttk.Entry(main_frame, textvariable=self.thread_count, width=10).grid(row=4, column=1, sticky=tk.W)
        
        ttk.Label(main_frame, text="Batch Size:").grid(row=5, column=0, sticky=tk.W, pady=2)
        self.batch_size = tk.StringVar(value="300")
        ttk.Entry(main_frame, textvariable=self.batch_size, width=10).grid(row=5, column=1, sticky=tk.W)
        
        ttk.Label(main_frame, text="Proxy (http://host:port):").grid(row=6, column=0, sticky=tk.W, pady=2)
        self.proxy_entry = ttk.Entry(main_frame, width=60)
        self.proxy_entry.grid(row=6, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        
  
        ttk.Label(main_frame, text="Output:").grid(row=7, column=0, sticky=tk.W, pady=2)
        self.output_text = tk.Text(main_frame, height=15, width=100, bg="3c3c3c", fg="ffffff", 
                                 insertbackground="ffffff", state="disabled")
        self.output_text.grid(row=8, column=0, columnspan=3, pady=2)
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        scrollbar.grid(row=8, column=3, sticky=(tk.N, tk.S))
        self.output_text['yscrollcommand'] = scrollbar.set
        

        self.output_text.tag_configure("info", foreground="ffffff")
        self.output_text.tag_configure("success", foreground="00ff00")
        self.output_text.tag_configure("error", foreground="ff4040")
        self.output_text.tag_configure("warning", foreground="ffa500")
        self.output_text.tag_configure("complete", foreground="40c4ff", font=("Helvetica", 10, "bold"))
        
   
        ttk.Button(main_frame, text="Start", command=self.start_scan).grid(row=9, column=0, pady=10)
        ttk.Button(main_frame, text="Stop", command=self.stop_scan).grid(row=9, column=1, pady=10)
        ttk.Button(main_frame, text="Clear Output", command=self.clear_output).grid(row=9, column=2, pady=10)
        ttk.Button(main_frame, text="Export Commits", command=self.export_commits).grid(row=9, column=3, pady=10)
    
    def log(self, message, tag="info"):
        self.output_text.configure(state="normal")
        self.output_text.insert(tk.END, message + "\n", tag)
        if tag == "success" and message.startswith("Found commit:"):
            self.commits.append(message)
        self.output_text.configure(state="disabled")
        self.output_text.see(tk.END)
        self.root.update()
    
    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)
    
    def export_commits(self):
        if not self.commits:
            messagebox.showinfo("Export", "No commits found to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"commits_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if filename:
            try:
                with open(filename, "w") as f:
                    f.write("\n".join(self.commits))
                messagebox.showinfo("Export", f"Commits exported successfully to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export commits: {str(e)}")
    
    def validate_inputs(self):
        if not self.token_entry.get():
            messagebox.showerror("Error", "GitHub token is required")
            return False
        
        if self.target_type.get() == "repository" and not self.target_entry.get():
            messagebox.showerror("Error", "Repository URL is required")
            return False
            
        if self.target_type.get() == "organization" and not (self.target_entry.get() or self.file_entry.get()):
            messagebox.showerror("Error", "Organization name or file is required")
            return False
            
        try:
            thread_count = int(self.thread_count.get())
            if thread_count < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Thread count must be a positive integer")
            return False
            
        try:
            batch_size = int(self.batch_size.get())
            if batch_size < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Batch size must be a positive integer")
            return False
            
        return True
    
    def build_graphql_query(self, commit_id_list, repository_name, repository_owner):
        commit_id_list = list(commit_id_list)
        query = 'query {repository(owner:"'+repository_owner+'",name:"'+repository_name+'"){'
        for idx, commit_id in enumerate(commit_id_list):
            query += f'a{idx}:object(expression:"{commit_id}"){{... on Commit {{oid}}}}'
        query += '}}'
        return query
    
    def query_commit_oids(self, short_sha_list, repository_name, repository_owner, retry_delay=10):
        query = self.build_graphql_query(short_sha_list, repository_name, repository_owner)
        headers = {"Authorization": f"Bearer {self.token_entry.get()}"}
        proxies = {"http": self.proxy_entry.get(), "https": self.proxy_entry.get()} if self.proxy_entry.get() else {}
        
        try:
            response = requests.post(
                'https://api.github.com/graphql',
                headers=headers,
                json={"query": query},
                proxies=proxies,
                verify=False
            )
        except Exception as e:
            self.log(f"Connection error: {e}", "error")
            time.sleep(retry_delay)
            return self.query_commit_oids(short_sha_list, repository_name, repository_owner, retry_delay + 2)
        
        if response.headers['Content-Type'].startswith('application/json'):
            response_data = response.json()
            if 'data' in response_data:
                if response_data['data'] is None:
                    error_msg = response_data.get('errors', [{}])[0].get('message', '')
                    if not error_msg.startswith("Something went wrong while executing your query"):
                        self.log(f"Query: {query}", "error")
                        self.log(str(response_data), "error")
                    self.log(f"JSON error, retrying in {retry_delay} seconds", "warning")
                    time.sleep(retry_delay)
                    return self.query_commit_oids(short_sha_list, repository_name, repository_owner, retry_delay + 2)
                
                valid_commits = []
                for commit_data in response_data['data']['repository'].values():
                    if commit_data:
                        valid_commits.append(commit_data['oid'])
                return valid_commits
            
            if 'message' in response_data and response_data['message'].startswith("You have exceeded a secondary rate limit"):
                self.log(f"Rate limited, retrying in {retry_delay} seconds", "warning")
            elif response_data.get('errors', [{}])[0].get('message', '').startswith("Parse error"):
                self.log('Parse error, skipping batch', "error")
                return []
            else:
                self.log(str(response_data), "error")
                self.log(f"Unexpected JSON response, retrying in {retry_delay} seconds", "warning")
            time.sleep(retry_delay)
            return self.query_commit_oids(short_sha_list, repository_name, repository_owner, retry_delay + 2)
        
        self.log(f"HTML response received, retrying in {retry_delay} seconds", "warning")
        time.sleep(retry_delay)
        return self.query_commit_oids(short_sha_list, repository_name, repository_owner, retry_delay + 2)
    
    def fetch_public_commits(self, repository_name, repository_owner):
        known_commits = set()
        self.log("Retrieving public commit history")
        headers = {"Authorization": f"Bearer {self.token_entry.get()}"}
        proxies = {"http": self.proxy_entry.get(), "https": self.proxy_entry.get()} if self.proxy_entry.get() else {}
        url = f'https://api.github.com/repos/{repository_owner}/{repository_name}/commits?per_page=100'
        
        while url and self.running:
            response = requests.get(url, headers=headers, proxies=proxies, verify=False)
            commit_data = response.json()
            for commit in commit_data:
                known_commits.add(commit["sha"])
            
            if 'link' in response.headers and "next" in response.headers['link']:
                next_link = [link for link in response.headers['link'].split(', ') if 'rel="next"' in link]
                if next_link:
                    url = next_link[0].split(';')[0].strip('<>')
                else:
                    url = None
            else:
                url = None
        
        self.log(f"Found {len(known_commits)} public commits", "success")
        return known_commits
    
    def graphql_query_worker(self, repository_name, repository_owner):
        while self.running:
            try:
                batch = self.commit_queue.get_nowait()
                valid_commits = self.query_commit_oids(batch, repository_name, repository_owner)
                for commit_id in valid_commits:
                    self.result_queue.put(commit_id)
                    self.log(f"Found commit: https://github.com/{repository_owner}/{repository_name}/commit/{commit_id}", "success")
                self.commit_queue.task_done()
            except queue.Empty:
                return
    
    def download_commit_diff(self, repository_name, repository_owner, commit_id):
        try:
            diff_url = f"https://github.com/{repository_owner}/{repository_name}/commit/{commit_id}.diff"
            response = requests.get(diff_url)
        except Exception as e:
            self.log(f"Download error: {e}", "error")
            return False
        
        if response.status_code == 200:
            output_file = f"output/{repository_owner}_{repository_name}/{commit_id}.diff"
            with open(output_file, "wb") as f:
                f.write(response.content)
            return True
        
        error_text = response.text
        if error_text.startswith("Content containing PDF or PS header bytes") or error_text.startswith("error: too big or took too long to generate"):
            self.log(f"Skipping large diff: {diff_url}", "warning")
            return True
        else:
            self.log(f"Diff download failed: {diff_url} (queue size: {self.result_queue.qsize()})", "error")
            return False
    
    def download_commit_patch(self, repository_name, repository_owner, commit_id):
        try:
            patch_url = f"https://github.com/{repository_owner}/{repository_name}/commit/{commit_id}.patch"
            response = requests.get(patch_url)
        except Exception as e:
            self.log(f"Download error: {e}", "error")
            return False
        
        if response.status_code == 200:
            output_file = f"output/{repository_owner}_{repository_name}/{commit_id}.patch"
            with open(output_file, "wb") as f:
                f.write(response.content)
            return True
        
        error_text = response.text
        if error_text.startswith("Content containing PDF or PS header bytes") or error_text.startswith("error: too big or took too long to generate"):
            self.log(f"Skipping large patch: {patch_url}", "warning")
            return True
        elif "This page is taking too long to load." in error_text:
            self.log(f"Skipping slow-loading commit: {patch_url}", "warning")
            return True
        else:
            self.log(f"Patch download failed: {patch_url} (queue size: {self.result_queue.qsize()})", "error")
            return False
    
    def diff_download_worker(self, repository_name, repository_owner):
        retry_delay = 2
        while self.running:
            try:
                commit_id = self.result_queue.get_nowait()
                if self.download_commit_diff(repository_name, repository_owner, commit_id):
                    self.result_queue.task_done()
                    retry_delay = max(2, retry_delay - 2)
                elif self.download_commit_patch(repository_name, repository_owner, commit_id):
                    self.result_queue.task_done()
                    retry_delay = max(2, retry_delay - 2)
                else:
                    self.result_queue.task_done()
                    self.result_queue.put(commit_id)
                    time.sleep(retry_delay)
                    retry_delay += 2
            except queue.Empty:
                return
    
    def populate_commit_queue(self, known_commits):
        hex_chars = "0123456789abcdef"
        current_batch = []
        batch_size = int(self.batch_size.get())
        
        for short_sha in product(hex_chars, repeat=4):
            if not self.running:
                break
            short_sha_str = ''.join(short_sha)
            collision_detected = False
            
            for full_sha in known_commits:
                if full_sha.startswith(short_sha_str):
                    collision_detected = True
                    for char in hex_chars:
                        extended_sha = f"{short_sha_str}{char}"
                        if not any(full_sha.startswith(extended_sha) for full_sha in known_commits):
                            current_batch.append(extended_sha)
                    break
            
            if not collision_detected:
                current_batch.append(short_sha_str)
            
            if len(current_batch) >= batch_size:
                self.commit_queue.put(current_batch)
                current_batch = []
        
        if current_batch and self.running:
            self.commit_queue.put(current_batch)
    
    def create_output_directory(self, repository_owner, repository_name):
        output_dir = os.path.join(os.getcwd(), f'output/{repository_owner}_{repository_name}')
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def run_repository_scan(self, repository_owner, repository_name):
        self.create_output_directory(repository_owner, repository_name)
        known_commits = self.fetch_public_commits(repository_name, repository_owner)
        if not self.running:
            return
            
        self.populate_commit_queue(known_commits)
        self.log(f"Prepared {self.commit_queue.qsize()} GraphQL queries")
        
        thread_count = int(self.thread_count.get())
        for _ in range(thread_count):
            worker = Thread(
                target=self.graphql_query_worker,
                args=(repository_name, repository_owner)
            )
            worker.daemon = True
            worker.start()
        
        self.commit_queue.join()
        self.log(f"Found {self.result_queue.qsize()} valid commits, downloading content")
        
        for _ in range(thread_count):
            worker = Thread(
                target=self.diff_download_worker,
                args=(repository_name, repository_owner)
            )
            worker.daemon = True
            worker.start()
        
        self.result_queue.join()
        if self.running:
            self.log(f"Repository scan completed successfully at {time.strftime('%H:%M:%S')}", "complete")
    
    def fetch_organization_repositories(self, organization_name):
        repositories = set()
        self.log(f"Retrieving repositories for {organization_name}")
        headers = {"Authorization": f"Bearer {self.token_entry.get()}"}
        proxies = {"http": self.proxy_entry.get(), "https": self.proxy_entry.get()} if self.proxy_entry.get() else {}
        url = f'https://api.github.com/users/{organization_name}/repos?per_page=100'
        
        while url and self.running:
            response = requests.get(url, headers=headers, proxies=proxies, verify=False)
            repo_data = response.json()
            for repo in repo_data:
                repositories.add(repo["name"])
            
            if 'link' in response.headers and "next" in response.headers['link']:
                next_link = [link for link in response.headers['link'].split(', ') if 'rel="next"' in link]
                url = next_link[0].split(';')[0].strip('<>') if next_link else None
            else:
                url = None
        
        self.log(f"Found {len(repositories)} repositories", "success")
        return repositories
    
    def scan_organization(self, organization_name):
        repositories = self.fetch_organization_repositories(organization_name)
        for repository in repositories:
            if not self.running:
                break
            self.run_repository_scan(organization_name, repository)
        if self.running:
            self.log(f"Organization scan of {organization_name} completed successfully at {time.strftime('%H:%M:%S')}", "complete")
    
    def start_scan(self):
        if not self.validate_inputs():
            return
            
        self.running = True
        self.commits.clear() 
        self.output_text.configure(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.configure(state="disabled")
        
        def scan_thread():
            try:
                if self.target_type.get() == "repository":
                    target = self.target_entry.get()
                    if "github.com" in target:
                        match = re.match(r"https?://github\.com/([^/]+)/([^/]+)", target)
                        if not match:
                            self.log("Invalid repository URL format", "error")
                            return
                        repo_owner, repo_name = match.groups()
                    else:
                        self.log("Please provide a valid GitHub repository URL", "error")
                        return
                    self.run_repository_scan(repo_owner, repo_name)
                    
                elif self.target_type.get() == "organization":
                    if self.file_entry.get():
                        organizations = set()
                        with open(self.file_entry.get()) as f:
                            for line in f:
                                cleaned_line = line.strip().replace('"', '')
                                if "github.com/" in cleaned_line:
                                    cleaned_line = cleaned_line.split("github.com/")[1]
                                organizations.add(cleaned_line.split("/")[0])
                        
                        self.log(f"Scanning {len(organizations)} organizations/users")
                        for org in organizations:
                            if not self.running:
                                break
                            self.scan_organization(org)
                    elif self.target_entry.get():
                        self.scan_organization(self.target_entry.get())
            except Exception as e:
                self.log(f"Error: {str(e)}", "error")
            finally:
                self.running = False
                if not self.running:
                    self.log("Scan stopped by user", "warning")
        
        Thread(target=scan_thread, daemon=True).start()
    
    def stop_scan(self):
        self.running = False
        self.log("Stopping scan...", "warning")
    
    def clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.configure(state="disabled")
        self.commits.clear()

if __name__ == "__main__":
    root = tk.Tk()
    app = GitHubCommitFinderGUI(root)
    root.mainloop()
