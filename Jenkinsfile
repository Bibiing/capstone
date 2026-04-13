pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    parameters {
        string(name: 'GIT_BRANCH', defaultValue: 'main', description: 'Git branch to build')
        string(name: 'DOCKER_IMAGE', defaultValue: 'hamasfa/jrisk-be', description: 'Target Docker image repository')
        string(name: 'DOCKER_REGISTRY_USER', defaultValue: 'hamasfa', description: 'Docker registry username for token-based login')
        booleanParam(name: 'CLEAN_DOCKER_CACHE', defaultValue: false, description: 'Prune Docker image cache after pipeline (set true if disk is limited)')
    }

    environment {
        SONARQUBE_ENV = 'sonarserver'
        SCANNER_HOME = tool 'sonarqube8.0'
        DOCKER_REGISTRY = 'docker.io'
        DOCKER_BUILDKIT = '1'
        PIP_CACHE_DIR = "${WORKSPACE}/.pip-cache"
        TESTS_PASSED = 'true'
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: params.GIT_BRANCH,
                    url: 'https://github.com/Bibiing/capstone',
                    credentialsId: 'jenkinsUser'
                script {
                    env.GIT_SHA_SHORT = sh(script: 'git rev-parse --short=8 HEAD', returnStdout: true).trim()
                    env.IMAGE_TAG = "${env.BUILD_NUMBER}-${env.GIT_SHA_SHORT}"
                    env.IMAGE_URI = "${params.DOCKER_IMAGE}:${env.IMAGE_TAG}"
                    env.IMAGE_LATEST = "${params.DOCKER_IMAGE}:latest"
                }
            }
        }

        stage('Test') {
            steps {
                script {
                    int testStatus = sh(
                        script: '''
                            set -e
                            git config --global --add safe.directory "${WORKSPACE}"
                            mkdir -p "${PIP_CACHE_DIR}"
                            docker run --rm \
                              -v "${WORKSPACE}:/app" \
                              -v "${PIP_CACHE_DIR}:/root/.cache/pip" \
                              -w /app \
                              python:3.11-slim \
                              sh -c '
                                  set -e
                                  rm -rf /app/.pytest_cache /app/.mypy_cache /app/.ruff_cache || true
                                  pip install --upgrade pip
                                  pip install -r requirements.txt
                                  set +e
                                  python -m pytest tests/ -q \
                                    -p no:cacheprovider \
                                    --junitxml=pytest-report.xml \
                                    --cov=api \
                                    --cov=database \
                                    --cov=config \
                                    --cov-report=xml:coverage.xml \
                                    --cov-report=term-missing
                                  test_status=$?
                                  set -e
                                  chmod -R a+rX /app/.pip-cache 2>/dev/null || true
                                  exit $test_status
                              '
                        ''',
                        returnStatus: true
                    )

                    if (testStatus != 0) {
                        env.TESTS_PASSED = 'false'
                        currentBuild.result = 'UNSTABLE'
                    } else {
                        env.TESTS_PASSED = 'true'
                    }
                }
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'pytest-report.xml'
                    archiveArtifacts artifacts: 'coverage.xml,pytest-report.xml', allowEmptyArchive: true
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv("${SONARQUBE_ENV}") {
                    sh '''
                        set -e
                        ${SCANNER_HOME}/bin/sonar-scanner \
                          -Dproject.settings=sonar-project.properties
                    '''
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 20, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('Build Docker Image') {
            when {
                expression {
                    return env.TESTS_PASSED == 'true'
                }
            }
            steps {
                sh '''
                    set -e
                    docker pull ${IMAGE_LATEST} || true
                    docker build --pull \
                      --cache-from ${IMAGE_LATEST} \
                      --build-arg BUILDKIT_INLINE_CACHE=1 \
                      -t ${IMAGE_URI} \
                      -t ${IMAGE_LATEST} \
                      .
                '''
            }
        }

        stage('Push Docker Image') {
            when {
                expression {
                    return env.TESTS_PASSED == 'true'
                }
            }
            steps {
                withCredentials([
                    string(
                        credentialsId: 'docker-registry-key',
                        variable: 'DOCKER_REGISTRY_KEY'
                    )
                ]) {
                    sh '''
                        set -e
                        if [ -z "${DOCKER_REGISTRY_USER}" ]; then
                            echo "DOCKER_REGISTRY_USER is required"
                            exit 1
                        fi

                        echo "${DOCKER_REGISTRY_KEY}" | docker login -u "${DOCKER_REGISTRY_USER}" --password-stdin ${DOCKER_REGISTRY}
                        docker push ${IMAGE_URI}
                        docker push ${IMAGE_LATEST}
                        docker logout ${DOCKER_REGISTRY}
                    '''
                }
            }
        }
    }

    post {
        success {
            echo "Pipeline sukses. Image: ${IMAGE_URI}"
        }
        unstable {
            echo 'Pipeline unstable: unit test gagal'
        }
        failure {
            echo 'Pipeline gagal'
        }
        always {
            script {
                if (params.CLEAN_DOCKER_CACHE) {
                    sh 'docker image prune -f || true'
                } else {
                    echo 'Skip docker prune to preserve cache for next build'
                }
            }
        }
    }
}