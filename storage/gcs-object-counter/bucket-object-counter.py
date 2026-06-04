from google.cloud import storage

def get_buckets_in_project(project_id):
   """Retrieves a list of buckets in the specified project."""
   client = storage.Client(project=project_id)
   buckets = client.list_buckets()
   return [bucket.name for bucket in buckets]

def get_object_count(bucket_name):
   """Counts the number of objects in a given bucket."""
   client = storage.Client()
   bucket = client.get_bucket(bucket_name)
   blobs = bucket.list_blobs(max_results=1000)  # Adjust max_results as needed
   object_count = 0
   for blob in blobs:
       object_count += 1
   return object_count

def main():
   project_id = input("Enter the project ID: ")
   try:
       buckets = get_buckets_in_project(project_id)
   except Exception as e:
       print(f"Error retrieving buckets: {e}")
       return
   
   print("Bucket Name\t\tObject Count")
   for bucket in buckets:
       try:
           object_count = get_object_count(bucket)
           print(f"{bucket}\t\t{object_count}")
       except Exception as e:
           print(f"Error counting objects in bucket {bucket}: {e}")

if __name__ == "__main__":
   main()
