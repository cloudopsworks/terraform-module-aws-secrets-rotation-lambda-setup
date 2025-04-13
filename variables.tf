##
# (c) 2024 - Cloud Ops Works LLC - https://cloudops.works/
#            On GitHub: https://github.com/cloudopsworks
#            Distributed Under Apache v2.0 License
#

# Establish this is a HUB or spoke configuration
variable "is_hub" {
  description = "Is this a hub or spoke configuration?"
  type        = bool
  default     = false
}

variable "spoke_def" {
  description = "Spoke ID Number, must be a 3 digit number"
  type        = string
  default     = "001"
  validation {
    condition     = (length(var.spoke_def) == 3) && tonumber(var.spoke_def) != null
    error_message = "The spoke_def must be a 3 digit number as string."
  }
}

variable "org" {
  description = "Organization details"
  type = object({
    organization_name = string
    organization_unit = string
    environment_type  = string
    environment_name  = string
  })
}

variable "extra_tags" {
  description = "Extra tags to add to the resources"
  type        = map(string)
  default     = {}
}
