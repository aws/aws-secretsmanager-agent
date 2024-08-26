# AWS Secrets Manager Agent

The AWS Secrets Manager Agent is a client\-side HTTP service that you can use to standardize consumption of secrets from Secrets Manager across environments such as AWS Lambda, Amazon Elastic Container Service, Amazon Elastic Kubernetes Service, and Amazon Elastic Compute Cloud\. The Secrets Manager Agent can retrieve and cache secrets in memory so that your applications can consume secrets directly from the cache\. That means you can fetch the secrets your application needs from the localhost instead of making calls to Secrets Manager\. The Secrets Manager Agent can only make read requests to Secrets Manager \- it can't modify secrets\. 

The Secrets Manager Agent uses the AWS credentials you provide in your environment to make calls to Secrets Manager\. The Secrets Manager Agent offers protection against Server Side Request Forgery \(SSRF\) to help improve secret security\. You can configure the Secrets Manager Agent by setting the maximum number of connections, the time to live \(TTL\), the localhost HTTP port, and the cache size\. 

Because the Secrets Manager Agent uses an in\-memory cache, it resets when the Secrets Manager Agent restarts\. The Secrets Manager Agent periodically refreshes the cached secret value\. The refresh happens when you try to read a secret from the Secrets Manager Agent after the TTL has expired\. The default refresh frequency \(TTL\) is 300 seconds, and you can change it by using a [Configuration file](#secrets-manager-agent-config) which you pass to the Secrets Manager Agent using the `--config` command line argument\. The Secrets Manager Agent does not include cache invalidation\. For example, if a secret rotates before the cache entry expires, the Secrets Manager Agent might return a stale secret value\. 

The Secrets Manager Agent returns secret values in the same format as the response of `GetSecretValue`\. Secret values are not encrypted in the cache\.

To download the source code, see [https://github\.com/aws/aws\-secretsmanager\-agent](https://github.com/aws/aws-secretsmanager-agent) on GitHub\.

**Topics**
- [AWS Secrets Manager Agent](#aws-secrets-manager-agent)
  - [Step 1: Build the Secrets Manager Agent binary](#step-1-build-the-secrets-manager-agent-binary)
      - [\[ RPM-based systems \]](#-rpm-based-systems-)
      - [\[ Debian-based systems \]](#-debian-based-systems-)
      - [\[ Windows \]](#-windows-)
      - [\[ Cross-compile natively \]](#-cross-compile-natively-)
      - [\[ Cross compile with Rust cross \]](#-cross-compile-with-rust-cross-)
  - [Step 2: Install the Secrets Manager Agent](#step-2-install-the-secrets-manager-agent)
      - [\[ Amazon EC2 \]](#-amazon-ec2-)
      - [\[ Running as a Container Sidecar \]](#-running-as-a-container-sidecar-)
      - [\[ AWS Lambda \]](#-aws-lambda-)
  - [Step 3: Retrieve secrets with the Secrets Manager Agent](#step-3-retrieve-secrets-with-the-secrets-manager-agent)
      - [\[ curl \]](#-curl-)
      - [\[ Python \]](#-python-)
  - [Configure the Secrets Manager Agent](#configure-the-secrets-manager-agent)
  - [Logging](#logging)
  - [Security considerations](#security-considerations)

## Step 1: Build the Secrets Manager Agent binary<a name="secrets-manager-agent-build"></a>

To build the Secrets Manager Agent binary natively, you need the standard development tools and the Rust tools\. Alternatively, you can cross\-compile for systems that support it, or you can use Rust cross to cross\-compile\.

------
#### [ RPM\-based systems ]

1. On RPM\-based systems such as AL2023, you can install the development tools by using the Development Tools group\.

   ```sh
   sudo yum -y groupinstall "Development Tools"
   ```

1. Follow the instructions at [Install Rust](https://www.rust-lang.org/tools/install) in the *Rust documentation*\.

   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh # Follow the on-screen instructions
   . "$HOME/.cargo/env"
   ```

1. Build the agent using the cargo build command:

   ```sh
   cargo build --release
   ```

   You will find the executable under `target/release/aws-secrets-manager-agent`\.

------
#### [ Debian\-based systems ]

1. On Debian\-based systems such as Ubuntu, you can install the developer tools using the build\-essential package\.

   ```sh
   sudo apt install build-essential
   ```

1. Follow the instructions at [Install Rust](https://www.rust-lang.org/tools/install) in the *Rust documentation*\.

   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh # Follow the on-screen instructions
   . "$HOME/.cargo/env"
   ```

1. Build the agent using the cargo build command:

   ```sh
   cargo build --release
   ```

   You will find the executable under `target/release/aws-secrets-manager-agent`\.

------
#### [ Windows ]

To build on Windows, follow the instructions at [Set up your dev environment on Windows for Rust](https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup) in the *Microsoft Windows documentation*\.

------
#### [ Cross\-compile natively ]

On distributions where the mingw\-w64 package is available such as Ubuntu, you can cross compile natively\.

```sh
# Install the cross compile tool chain
sudo add-apt-repository universe
sudo apt install -y mingw-w64
    
# Install the rust build targets
rustup target add x86_64-pc-windows-gnu
    
# Cross compile the agent for Windows
cargo build --release --target x86_64-pc-windows-gnu
```

You will find the executable at `target/x86_64-pc-windows-gnu/release/aws-secrets-manager-agent.exe`\.

------
#### [ Cross compile with Rust cross ]

If the cross compile tools are not available natively on the system, you can use the Rust cross project\. For more information, see [https://github\.com/cross\-rs/cross](https://github.com/cross-rs/cross)\.

**Important**  
We recommend 32GB disk space for the build environment\.

```sh
# Install and start docker
sudo yum -y install docker
sudo systemctl start docker
sudo systemctl enable docker # Make docker start after reboot
    
# Give ourselves permission to run the docker images without sudo
sudo usermod -aG docker $USER
newgrp docker
    
# Install cross and cross compile the executable
cargo install cross
cross build --release --target x86_64-pc-windows-gnu
```

------

## Step 2: Install the Secrets Manager Agent<a name="secrets-manager-agent-install"></a>

Based on the type of compute, you have several options for installing the Secrets Manager Agent\.

------
#### [ Amazon EC2 ]

**To install the Secrets Manager Agent**

1. Use the `install` script provided in the repository\. 

   The script generates a random SSRF token on startup and stores it in the file `/var/run/awssmatoken`\. The token is readable by the `awssmatokenreader` group that the install script creates\. 

1. To allow your application to read the token file, you need to add the user account that your application runs under to the `awssmatokenreader` group\. For example, you can grant permissions for your application to read the token file with the following usermod command, where *<APP\_USER>* is the user ID under which your application runs\.

   ```sh
   sudo usermod -aG awssmatokenreader <APP_USER>
   ```

------
#### [ Running as a Container Sidecar ]

You can run the Secrets Manager Agent as a sidecar container alongside your application by using Docker\. Then your application can retrieve secrets from the local HTTP server the Secrets Manager Agent provides\. For information about Docker, see the [Docker documentation](https://docs.docker.com)\. 

**To create a sidecar container for the Secrets Manager Agent with Docker**

1. Create a Dockerfile for the Secrets Manager Agent sidecar container\. The following example creates a Docker container with the Secrets Manager Agent binary\.

   ```dockerfile
   # Use the latest Debian image as the base
   FROM debian:latest
   
   # Set the working directory inside the container
   WORKDIR /app 
   
   # Copy the Secrets Manager Agent binary to the container
   COPY secrets-manager-agent . 
   
   # Install any necessary dependencies
   RUN apt-get update && apt-get install -y ca-certificates 
   
   # Set the entry point to run the Secrets Manager Agent binary
   ENTRYPOINT ["./secrets-manager-agent"]
   ```

1. Create a Dockerfile for your client application\.

1. Create a Docker Compose file to run both containers, being sure that they use the same network interface\. This is necessary because the Secrets Manager Agent does not accept requests from outside the localhost interface\. The following example shows a Docker Compose file where the `network_mode` key attaches the `secrets-manager-agent` container to the network namespace of the `client-application` container, which allows them to share the same network interface\.
**Important**  
You must load AWS credentials and the SSRF token for the application to be able to use the Secrets Manager Agent\. See the following:  
[Manage access](https://docs.aws.amazon.com/eks/latest/userguide/cluster-auth.html) in the *Amazon Elastic Kubernetes Service User Guide*
[Amazon ECS task IAM role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html) in the *Amazon Elastic Container Service Developer Guide*

   ```yaml
   version: '3'
   services:
       client-application:
       container_name: client-application
       build:
           context: .
           dockerfile: Dockerfile.client
       command: tail -f /dev/null  # Keep the container running
       
   
       secrets-manager-agent:
       container_name: secrets-manager-agent
       build:
           context: .
           dockerfile: Dockerfile.agent
       network_mode: "container:client-application"  # Attach to the client-application container's network
       depends_on:
           - client-application
   ```

1. Copy the `secrets-manager-agent` binary to the same directory that contains your Dockerfiles and Docker Compose file\.

1. Build and run the containers based on the provided Dockerfiles by using the following [https://docs.docker.com/reference/cli/docker/compose/](https://docs.docker.com/reference/cli/docker/compose/) command\.

   ```sh
   docker-compose up --build
   ```

1. In your client container, you can now use the Secrets Manager Agent to retrieve secrets\. For more information, see [Step 3: Retrieve secrets with the Secrets Manager Agent](#secrets-manager-agent-call)\.

------
#### [ AWS Lambda ]

You can [package the Secrets Manager Agent as an AWS Lambda extension](https://docs.aws.amazon.com/lambda/latest/dg/packaging-layers.html)\. Then you can [add it to your Lambda function as a layer](https://docs.aws.amazon.com/lambda/latest/dg/adding-layers.html) and call the Secrets Manager Agent from your Lambda function to get secrets\. 

The following instructions show how to get a secret named *MyTest* by using the example script `secrets-manager-agent-extension.sh` in [https://github\.com/aws/aws\-secretsmanager\-agent](https://github.com/aws/aws-secretsmanager-agent) to install the Secrets Manager Agent as a Lambda extension\.

**To create a Lambda extension that packages the Secrets Manager Agent**

1. Create a Python Lambda function that queries `http://localhost:2773/secretsmanager/get?secretId=MyTest` to get the secret\. Be sure to implement retry logic in your application code to accommodate delays in initialization and registration of the Lambda extension\.

1. From the root of the Secrets Manager Agent code package, run the following commands to test the Lambda extension\.

   ```sh
   AWS_ACCOUNT_ID=<AWS_ACCOUNT_ID>
   LAMBDA_ARN=<LAMBDA_ARN>
   
   # Build the release binary 
   cargo build --release --target=x86_64-unknown-linux-gnu
   
   # Copy the release binary into the `bin` folder
   mkdir -p ./bin
   cp ./target/x86_64-unknown-linux-gnu/release/aws_secretsmanager_agent ./bin/secrets-manager-agent
   
   # Copy the `secrets-manager-agent-extension.sh` script into the `extensions` folder.
   mkdir -p ./extensions
   cp aws_secretsmanager_agent/examples/example-lambda-extension/secrets-manager-agent-extension.sh ./extensions
   
   # Zip the extension shell script and the binary 
   zip secrets-manager-agent-extension.zip bin/* extensions/*
   
   # Publish the layer version
   LAYER_VERSION_ARN=$(aws lambda publish-layer-version \
       --layer-name secrets-manager-agent-extension \
       --zip-file "fileb://secrets-manager-agent-extension.zip" | jq -r '.LayerVersionArn')
   
   # Attach the layer version to the Lambda function
   aws lambda update-function-configuration \
       --function-name $LAMBDA_ARN \
       --layers "$LAYER_VERSION_ARN"
   ```

1. Invoke the Lambda function to verify that the secret is being correctly fetched\. 

------

## Step 3: Retrieve secrets with the Secrets Manager Agent<a name="secrets-manager-agent-call"></a>

To use the agent, you call the local Secrets Manager Agent endpoint and include the name or ARN of the secret as a query parameter\. By default, the Secrets Manager Agent retrieves the `AWSCURRENT` version of the secret\. To retrieve a different version, you can set `versionStage` or `versionId`\.

To help protect the Secrets Manager Agent, you must include a SSRF token header as part of each request: `X-Aws-Parameters-Secrets-Token`\. The Secrets Manager Agent denies requests that don't have this header or that have an invalid SSRF token\. You can customize the SSRF header name in the [Configuration file](#secrets-manager-agent-config)\.

The Secrets Manager Agent uses the AWS SDK for Rust, which uses the [https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html)\. The identity of these IAM credentials determines the permissions the Secrets Manager Agent has to retrieve secrets\. 

**Required permissions: **
+ `secretsmanager:DescribeSecret`
+ `secretsmanager:GetSecretValue`

For more information, see [Permissions reference](reference_iam-permissions.md)\.

**Important**  
After the secret value is pulled into the Secrets Manager Agent, any user with access to the compute environment and SSRF token can access the secret from the Secrets Manager Agent cache\. For more information, see [Security considerations](#secrets-manager-agent-security)\.

------
#### [ curl ]

The following curl example shows how to get a secret from the Secrets Manager Agent\. The example relies on the SSRF being present in a file, which is where it is stored by the install script\.

```sh
curl -v -H \
    "X-Aws-Parameters-Secrets-Token: $(</var/run/awssmatoken)" \
    'http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>}'; \
    echo
```

------
#### [ Python ]

The following Python example shows how to get a secret from the Secrets Manager Agent\. The example relies on the SSRF being present in a file, which is where it is stored by the install script\.

```python
import requests
import json

# Function that fetches the secret from Secrets Manager Agent for the provided secret id. 
def get_secret():
    # Construct the URL for the GET request
    url = f"http://localhost:2773/secretsmanager/get?secretId=<YOUR_SECRET_ID>}"

    # Get the SSRF token from the token file
    with open('/var/run/awssmatoken') as fp:
        token = fp.read() 

    headers = {
        "X-Aws-Parameters-Secrets-Token": token.strip()
    }

    try:
        # Send the GET request with headers
        response = requests.get(url, headers=headers)

        # Check if the request was successful
        if response.status_code == 200:
            # Return the secret value
            return response.text
        else:
            # Handle error cases
            raise Exception(f"Status code {response.status_code} - {response.text}")

    except Exception as e:
        # Handle network errors
        raise Exception(f"Error: {e}")
```

------

## Configure the Secrets Manager Agent<a name="secrets-manager-agent-config"></a>

To change the configuration of the Secrets Manager Agent, create a [TOML](https://toml.io/en/) config file, and then call `./aws-secrets-manager-agent --config config.toml`\.

The following list shows the options you can configure for the Secrets Manager Agent\.
+ **log\_level** – The level of detail reported in logs for the Secrets Manager Agent: DEBUG, INFO, WARN, ERROR, or NONE\. The default is INFO\.
+ **http\_port** – The port for the local HTTP server, in the range 1024 to 65535\. The default is 2773\.
+ **region** – The AWS Region to use for requests\. If no Region is specified, the Secrets Manager Agent determines the Region from the SDK\. For more information, see [Specify your credentials and default Region](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html) in the *AWS SDK for Rust Developer Guide*\.
+ **ttl\_seconds** – The TTL in seconds for the cached items, in the range 1 to 3600\. The default is 300\. This setting is not used if the cache size is 0\. 
+ **cache\_size** – The maximum number of secrets that can be stored in the cache, in the range 0 to 1000\. 0 indicates that there is no caching\. The default is 1000\. 
+ **ssrf\_headers** – A list of header names the Secrets Manager Agent checks for the SSRF token\. The default is "X\-Aws\-Parameters\-Secrets\-Token, X\-Vault\-Token"\. 
+ **ssrf\_env\_variables** – A list of environment variable names the Secrets Manager Agent checks for the SSRF token\. The environment variable can contain the token or a reference to the token file as in: `AWS_TOKEN=file:///var/run/awssmatoken`\. The default is "AWS\_TOKEN, AWS\_SESSION\_TOKEN"\.
+ **path\_prefix** – The URI prefix used to determine if the request is a path based request\. The default is "/v1/"\.
+ **max\_conn** – The maximum number of connections from HTTP clients that the Secrets Manager Agent allows, in the range 1 to 1000\. The default is 800\.

## Logging<a name="secrets-manager-agent-log"></a>

The Secrets Manager Agent logs errors locally to the file `logs/secrets_manager_agent.log`\. When your application calls the Secrets Manager Agent to get a secret, those calls appear in the local log\. They do not appear in the CloudTrail logs\. 

The Secrets Manager Agent creates a new log file when the file reaches 10 MB, and it stores up to five log files total\. 

The log does not go to Secrets Manager, CloudTrail, or CloudWatch\. Requests to get secrets from the Secrets Manager Agent do not appear in those logs\. When the Secrets Manager Agent makes a call to Secrets Manager to get a secret, that call is recorded in CloudTrail with a user agent string containing `aws-secrets-manager-agent`\. 

You can configure logging in the [Configuration file](#secrets-manager-agent-config)\. 

## Security considerations<a name="secrets-manager-agent-security"></a>

For an agent architecture, the domain of trust is where the agent endpoint and SSRF token are accessible, which is usually the entire host\. The domain of trust for the Secrets Manager Agent should match the domain where the Secrets Manager credentials are available in order to maintain the same security posture\. For example, on Amazon EC2 the domain of trust for the Secrets Manager Agent would be the same as the domain of the credentials when using roles for Amazon EC2\.

Security conscious applications that are not already using an agent solution with the Secrets Manager credentials locked down to the application should consider using the language\-specific AWS SDKs or caching solutions\. For more information, see [Get secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/retrieving-secrets.html)\.
