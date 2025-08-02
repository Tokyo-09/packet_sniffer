pipeline {
    agent any
    environment {
        // Ensure Rust is in PATH
        PATH = "$PATH:/home/jenkins/.cargo/bin"
    }

    stages {
        stage('Build') {
            steps {
                sh "cargo build"
            }
        }
        stage('Test') {
            steps {
                sh "cargo test"
            }
        }
        stage('Clippy') {
            steps {
                sh "cargo +nightly clippy --all"
            }
        }
        stage('Rustfmt') {
            steps {
                sh "cargo +nightly fmt --all -- --write-mode diff"
            }
        }
        }
    }
}
