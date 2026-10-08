output "instance_id" {
  value = aws_instance.target.id
}
output "private_ip" {
  value = aws_instance.target.private_ip
}
output "public_ip" {
  value = aws_instance.target.public_ip
}
output "log_group_names" {
  value = { for key, group in aws_cloudwatch_log_group.target : key => group.name }
}
