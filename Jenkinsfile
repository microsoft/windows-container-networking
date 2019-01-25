pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
               bat '''
               set GOPATH=%cd%
               cd src/github.com/Microsoft/windows-container-networking
               make all
               '''
           }
        }
        stage('Test') {
             steps {
               bat '''
               set GOPATH=%cd%
               go env
               cd src/github.com/Microsoft/windows-container-networking
               make test
               '''
            }
        }
    }
}
