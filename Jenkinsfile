pipeline {
    agent any
    
    environment {
        BUILD_ID = "${env.BUILD_NUMBER}"
        NODE_ENV = "production"
        GIT_COMMIT = "${env.GIT_COMMIT}"
    }
    
    stages {
        stage('Verify Environment') {
            steps {
                sh 'python3 environment_scanner.py'
                sh 'SNAPSHOT=$(ls -t snapshots/*.json | head -1) && python3 attestation_generator.py $SNAPSHOT'
            }
        }
        
        stage('Archive Attestation') {
            steps {
                archiveArtifacts artifacts: 'attestations/*.json', fingerprint: true
            }
        }
    }
}