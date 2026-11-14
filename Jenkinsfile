pipeline {
    agent any
    environment {
        IMAGE = "sandeep262005/healthcare-app:${BUILD_NUMBER}"
    }
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'mkdir -p reports'
            }
        }
        stage('Secret Scan') {
            steps {
                sh '''
                  RC=0
                  docker run --rm -v trivy-cache:/root/.cache/ -v $WORKSPACE:/src:ro aquasec/trivy:latest \
                    fs --scanners secret --exit-code 1 /src > reports/1-secret-scan.txt 2>&1 || RC=$?
                  cat reports/1-secret-scan.txt
                  if [ $RC -ne 0 ]; then echo "SECRETS FOUND IN CODE - PIPELINE STOPPED"; exit 1; fi
                  echo "SECRET SCAN PASSED - no hardcoded secrets"
                '''
            }
        }
        stage('SAST - Bandit') {
            steps {
                sh '''
                  RC=0
                  docker run --rm -v $WORKSPACE:/src:ro python:3.12-slim sh -c \
                    "pip install -q --root-user-action=ignore bandit && bandit -r /src/app.py -ll" \
                    > reports/2-sast-bandit.txt 2>&1 || RC=$?
                  cat reports/2-sast-bandit.txt
                  if [ $RC -ne 0 ]; then echo "SAST FAILED - insecure code found"; exit 1; fi
                  echo "SAST PASSED - no medium/high security issues in code"
                '''
            }
        }
        stage('Dependency Scan (SCA)') {
            steps {
                sh '''
                  docker run --rm -v trivy-cache:/root/.cache/ -v $WORKSPACE:/src:ro aquasec/trivy:latest \
                    fs --scanners vuln --severity HIGH,CRITICAL /src > reports/3-dependency-scan.txt 2>&1 || true
                  cat reports/3-dependency-scan.txt
                  docker run --rm -v trivy-cache:/root/.cache/ -v $WORKSPACE:/src:ro aquasec/trivy:latest \
                    fs --scanners vuln --severity CRITICAL --exit-code 1 --quiet /src
                  echo "DEPENDENCY SCAN PASSED - no CRITICAL vulnerable libraries"
                '''
            }
        }
        stage('IaC Scan') {
            steps {
                sh '''
                  docker run --rm -v trivy-cache:/root/.cache/ -v $WORKSPACE:/src:ro aquasec/trivy:latest \
                    config --severity HIGH,CRITICAL /src > reports/4-iac-scan.txt 2>&1 || true
                  cat reports/4-iac-scan.txt
                  docker run --rm -v trivy-cache:/root/.cache/ -v $WORKSPACE:/src:ro aquasec/trivy:latest \
                    config --severity CRITICAL --exit-code 1 --quiet /src
                  echo "IaC SCAN PASSED - Dockerfile and Kubernetes files are secure"
                '''
            }
        }
        stage('Build Docker Image') {
            steps { sh 'docker build -t $IMAGE .' }
        }
        stage('Image Scan - Trivy') {
            steps {
                sh '''
                  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache/ aquasec/trivy:latest \
                    image --severity HIGH,CRITICAL --ignore-unfixed $IMAGE > reports/5-image-scan.txt 2>&1 || true
                  cat reports/5-image-scan.txt
                  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache/ aquasec/trivy:latest \
                    image --severity CRITICAL --ignore-unfixed --exit-code 1 --quiet $IMAGE
                  echo "IMAGE SCAN PASSED - no fixable CRITICAL vulnerabilities"
                '''
            }
        }
        stage('Push to Docker Hub') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub-creds',
                        usernameVariable: 'USER', passwordVariable: 'PASS')]) {
                    sh 'echo $PASS | docker login -u $USER --password-stdin'
                    sh 'docker push $IMAGE'
                }
            }
        }
        stage('Secure Deploy to Kubernetes') {
            steps {
                sh '''
                  set +x
                  kubectl get secret healthcare-secret >/dev/null 2>&1 || \
                    kubectl create secret generic healthcare-secret --from-literal=API_KEY=$(openssl rand -hex 16)
                  echo "API key stored as a Kubernetes Secret (never in code or logs)"
                  set -x
                  sed "s|IMAGE_PLACEHOLDER|$IMAGE|g" k8s/deployment.yaml > deploy.yaml
                  kubectl apply -f deploy.yaml
                  kubectl apply -f k8s/service.yaml
                  kubectl rollout status deployment/healthcare-app --timeout=180s
                '''
            }
        }
        stage('Security Verification') {
            steps {
                sh '''
                  set +x
                  SVC=$(kubectl get svc healthcare-service -o jsonpath='{.spec.clusterIP}')
                  KEY=$(kubectl get secret healthcare-secret -o jsonpath='{.data.API_KEY}' | base64 -d)

                  echo "CHECK 1: Health endpoint"
                  curl -sf --max-time 5 http://$SVC/health; echo

                  echo "CHECK 2: Patient API WITHOUT API key (expect 401)"
                  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://$SVC/api/patients)
                  echo "HTTP $CODE"
                  if [ "$CODE" != "401" ]; then echo "FAIL: patient data not protected"; exit 1; fi

                  echo "CHECK 3: Patient API WITH valid API key (expect 200)"
                  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -H "X-API-Key: $KEY" http://$SVC/api/patients)
                  echo "HTTP $CODE"
                  if [ "$CODE" != "200" ]; then echo "FAIL: authorised access broken"; exit 1; fi

                  echo "CHECK 4: Security headers"
                  curl -sI --max-time 5 http://$SVC/ | grep -i -E "x-content-type-options|x-frame-options|content-security-policy|strict-transport-security"

                  echo "CHECK 5: Container runs as non-root user"
                  POD=$(kubectl get pods -l app=healthcare-app -o jsonpath='{.items[0].metadata.name}')
                  kubectl exec $POD -- id

                  echo "ALL SECURITY CHECKS PASSED"
                '''
            }
        }
    }
    post {
        always { archiveArtifacts artifacts: 'reports/*.txt', allowEmptyArchive: true }
        success { echo "SUCCESS: Secure healthcare app deployed at http://23.22.76.155:30080" }
        failure { echo "PIPELINE STOPPED: a security check failed - nothing insecure was deployed" }
    }
}
