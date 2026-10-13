resource "aws_s3_bucket" "data" {
  bucket = "llm-training-data"
  acl    = "public-read"
}

resource "aws_security_group" "open" {
  name = "open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
