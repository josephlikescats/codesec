"""Jenkins Integration

Provides integration with Jenkins for automated security scanning.
"""

import logging
from typing import Any, Optional
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class JenkinsConfig:
    """Configuration for Jenkins integration."""
    url: str = "http://localhost:8080"
    username: Optional[str] = None
    token: Optional[str] = None
    job_name: str = "securecode-scan"


@dataclass
class JenkinsScanResult:
    """Result from Jenkins scan."""
    build_number: int
    status: str
    findings: list[dict] = field(default_factory=list)
    duration: float = 0.0
    artifacts: dict = field(default_factory=dict)


class JenkinsIntegration:
    """Jenkins pipeline integration for security scanning."""
    
    JENKINSFILE_TEMPLATE = '''pipeline {
    agent any
    
    environment {
        SECURECODE_API_KEY = credentials('securecode-api-key')
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Security Scan') {
            steps {
                script {
                    sh '''
                        pip install securecode-ai
                        securecode scan --output scan-results.json --format json
                    '''
                }
            }
        }
        
        stage('Analyze Results') {
            steps {
                script {
                    def results = readJSON file: 'scan-results.json'
                    
                    def criticalCount = results.findings.count { it.severity == 'critical' }
                    def highCount = results.findings.count { it.severity == 'high' }
                    
                    echo "Security Scan Results:"
                    echo "  Critical: ${criticalCount}"
                    echo "  High: ${highCount}"
                    
                    // Fail build on critical findings
                    if (criticalCount > 0) {
                        error "Build failed: ${criticalCount} critical security vulnerabilities found"
                    }
                }
            }
        }
        
        stage('Generate Tests') {
            steps {
                script {
                    sh '''
                        securecode generate-tests --input scan-results.json --output tests/
                    '''
                }
            }
        }
        
        stage('Archive Results') {
            steps {
                archiveArtifacts artifacts: 'scan-results.json,tests/**', allowEmptyArchive: true
                publishHTML target: [
                    reportDir: 'reports',
                    reportName: 'Security Report',
                    reportFiles: 'index.html'
                ]
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        failure {
            emailext (
                subject: "Jenkins Build Failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: "Security scan found critical vulnerabilities. Check the build logs for details.",
                to: "${env.DEFAULT_RECIPIENTS}"
            )
        }
    }
}
'''
    
    def __init__(self, config: Optional[JenkinsConfig] = None):
        self.config = config or JenkinsConfig()
    
    def generate_jenkinsfile(self, output_path: str = "Jenkinsfile") -> str:
        """Generate Jenkinsfile for security scanning."""
        with open(output_path, "w") as f:
            f.write(self.JENKINSFILE_TEMPLATE)
        
        logger.info(f"Generated Jenkinsfile at {output_path}")
        return output_path
    
    def generate_job_config(self, output_path: str = "jenkins-job-config.xml") -> str:
        """Generate Jenkins job configuration XML."""
        config_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<project>
  <description>SecureCode AI Security Scan Pipeline</description>
  <keepDependencies>false</keepDependencies>
  <properties>
    <com.dabsquared.gitlabjenkins.connection.GitLabConnectionProperty>
      <gitLabConnection>gitlab</gitLabConnection>
    </com.dabsquared.gitlabjenkins.connection.GitLabConnectionProperty>
  </properties>
  <scm class="hudson.plugins.git.GitSCM">
    <configVersion>2</configVersion>
    <userRemoteConfigs>
      <hudson.plugins.git.UserRemoteConfig>
        <url>${GIT_REPO_URL}</url>
      </hudson.plugins.git.UserRemoteConfig>
    </userRemoteConfigs>
    <branches>
      <hudson.plugins.git.BranchSpec>
        <name>*/main</name>
      </hudson.plugins.git.BranchSpec>
    </branches>
  </scm>
  <canRoam>true</canRoam>
  <disabled>false</disabled>
  <blockBuildWhenDownstreamBuilding>false</blockBuildWhenDownstreamBuilding>
  <blockBuildWhenUpstreamBuilding>false</blockBuildWhenUpstreamBuilding>
  <triggers>
    <hudson.triggers.SCMTrigger>
      <spec>H/5 * * * *</spec>
      <ignorePostCommitHooks>false</ignorePostCommitHooks>
    </hudson.triggers.SCMTrigger>
  </triggers>
  <concurrentBuild>false</concurrentBuild>
  <builders>
    <hudson.tasks.Shell>
      <command>pip install securecode-ai && securecode scan --output scan-results.json</command>
    </hudson.tasks.Shell>
  </builders>
  <publishers>
    <hudson.tasks.Mailer>
      <recipients>team@example.com</recipients>
      <dontNotifyEveryUnstableBuild>false</dontNotifyEveryUnstableBuild>
      <sendToIndividuals>false</sendToIndividuals>
    </hudson.tasks.Mailer>
  </publishers>
  <buildWrappers/>
</project>
'''
        
        with open(output_path, "w") as f:
            f.write(config_xml)
        
        logger.info(f"Generated Jenkins job config at {output_path}")
        return output_path
    
    async def trigger_scan(self, parameters: Optional[dict] = None) -> str:
        """Trigger a Jenkins build for security scanning."""
        # This would use Jenkins API in production
        return "build_number"
    
    async def get_scan_results(self, build_number: int) -> JenkinsScanResult:
        """Get scan results from Jenkins build."""
        # This would fetch results from Jenkins API in production
        return JenkinsScanResult(
            build_number=build_number,
            status="SUCCESS",
            findings=[]
        )


def create_jenkinsfile(output_path: str = "Jenkinsfile") -> str:
    """Create Jenkinsfile for security scanning."""
    integration = JenkinsIntegration()
    return integration.generate_jenkinsfile(output_path)


# Example usage
def main():
    jenkinsfile_path = create_jenkinsfile()
    print(f"Created Jenkinsfile at: {jenkinsfile_path}")
    
    config_path = JenkinsIntegration().generate_job_config()
    print(f"Created Jenkins config at: {config_path}")


if __name__ == "__main__":
    main()