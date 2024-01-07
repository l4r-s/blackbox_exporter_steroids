
import os
import json
import bcrypt
import subprocess
import logging
from jinja2 import Template
from concurrent.futures import ThreadPoolExecutor

regions = [
   { "name": "asia-east1", "multi_region": "as" },
   { "name": "asia-east2", "multi_region": "as" },
   { "name": "asia-northeast1", "multi_region": "as" },
   { "name": "asia-northeast2", "multi_region": "as" },
   { "name": "asia-northeast3", "multi_region": "as" },
   { "name": "asia-south1", "multi_region": "as" },
   { "name": "asia-south2", "multi_region": "as" },
   { "name": "asia-southeast1", "multi_region": "as" },
   { "name": "asia-southeast2", "multi_region": "as" },
   { "name": "australia-southeast1", "multi_region": "as" },
   { "name": "australia-southeast2", "multi_region": "as" },
   { "name": "europe-central2", "multi_region": "eu" },
   { "name": "europe-north1", "multi_region": "eu" },
   { "name": "europe-southwest1", "multi_region": "eu" },
   { "name": "europe-west1", "multi_region": "eu" },
   { "name": "europe-west10", "multi_region": "eu" },
   { "name": "europe-west12", "multi_region": "eu" },
   { "name": "europe-west2", "multi_region": "eu" },
   { "name": "europe-west3", "multi_region": "eu" },
   { "name": "europe-west4", "multi_region": "eu" },
   { "name": "europe-west6", "multi_region": "eu" },
   { "name": "europe-west8", "multi_region": "eu" },
   { "name": "europe-west9", "multi_region": "eu" },
   { "name": "me-central1", "multi_region": "eu" },
   { "name": "me-central2", "multi_region": "eu" },
   { "name": "me-west1", "multi_region": "eu" },
   { "name": "northamerica-northeast1", "multi_region": "us" },
   { "name": "northamerica-northeast2", "multi_region": "us" },
   { "name": "southamerica-east1", "multi_region": "us" },
   { "name": "southamerica-west1", "multi_region": "us" },
   { "name": "us-central1", "multi_region": "us" },
   { "name": "us-east1", "multi_region": "us" },
   { "name": "us-east4", "multi_region": "us" },
   { "name": "us-east5", "multi_region": "us" },
   { "name": "us-south1", "multi_region": "us" },
   { "name": "us-west1", "multi_region": "us" },
   { "name": "us-west2", "multi_region": "us" },
   { "name": "us-west3", "multi_region": "us" },
   { "name": "us-west4", "multi_region": "us" }
]

repo_urls = {
    "as": "asia-docker.pkg.dev/pinginator-408420/as",
    "us": "us-docker.pkg.dev/pinginator-408420/us",
    "eu": "europe-docker.pkg.dev/pinginator-408420/eu"
}

auht_secret = "U3QwokM6DtnJ2Cbs6JRLqgzYQdAWdc"
image_name = "blackbox-http"
tag = "399c5cfada0f5b629ae6ded6b881133db5658e1b"

def generate_bcrypt_hash(secret):
    # Convert the secret to bytes, if it's not already
    secret_bytes = secret.encode('utf-8')

    # Generate salt
    salt = bcrypt.gensalt()

    # Generate the bcrypt hash
    hashed_secret = bcrypt.hashpw(secret_bytes, salt)

    return hashed_secret.decode("utf-8")

def deploy_gcloud_run_service(script_dir, region, logger):
    try:
        command = ["gcloud", "run", "services", "replace", f"{script_dir}/out/{region}.yml"]
        subprocess.run(command, check=True)
        logger.info(f"Deployed region {region}!")

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to deploy region {region}: {e}")

def allow_all_ingress_gcloud_run_service(region, logger):
    try:
        command = [
            "gcloud",
            "run",
            "services",
            "add-iam-policy-binding", region,
            "--member=allUsers",
            "--role=roles/run.invoker",
            "--region", region
        ]
        subprocess.run(command, check=True)
        logger.info(f"Allowed all ingress on {region}!")

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to allow all ingress on region {region}: {e}")


def create_service_file(template_path, template_data, region, out_folder):
    with open(template_path, 'r') as file:
        template_content = file.read()

    template = Template(template_content)

    rendered_template = template.render(template_data)
    out_folder = out_folder.rstrip("/")
    with open(f"{out_folder}/{region}.yml", 'w') as file:
        file.write(rendered_template)

def get_cloud_run_service_urls(logger):
    try:
        # Run the gcloud command
        result = subprocess.run(
            ["gcloud", "run", "services", "list", "--format=json"],
            capture_output=True, text=True, check=True)

        services = {}
        out = json.loads(result.stdout)

        for service in out:
            services[service["metadata"]["name"]] = service["status"]["url"]

        return services

    except subprocess.CalledProcessError as e:
        logger.error(f"Error occurred while getting urls: {e}")
        return {}

def deploy_region(region_data):
    script_dir, region, logger = region_data
    logger.info(f"Working on {region}")

    deploy_gcloud_run_service(script_dir, region, logger)
    allow_all_ingress_gcloud_run_service(region, logger)

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))

    logger.info("Creating service files...")
    region_data_list = []
    for r in regions:
        region = r["name"]
        multi_region = r["multi_region"]
        repo_url = repo_urls[multi_region].rstrip("/")

        image = f"{repo_url}/{image_name}:{tag}"
        #logger.info(f"Working on {region}\n  repo_url: {repo_url}\n  image_url: {image}")

        auth_token = generate_bcrypt_hash(auht_secret)

        # cerate template
        template_data = {
            "region": region,
            "image": image,
            "auth_token": auth_token
        }
        create_service_file(
            template_path = f"{script_dir}/template.yml",
            template_data = template_data,
            region = region,
            out_folder = f"{script_dir}/out/"
        )

        region_data_list.append((script_dir, region, logger))


    # Deploy in parallel
    logger.info("Starting deployment...")
    with ThreadPoolExecutor() as executor:
        executor.map(deploy_region, region_data_list)

    urls = get_cloud_run_service_urls(logger=logger)
    print(json.dumps(urls, indent=2))