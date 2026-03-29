using System;
using System.Collections;

namespace Unifi {
    public class User {

        public string   ID                          { get; set; }
        public string   Name                        { get; set; }
        public string   Email                       { get; set; }
        public string   DeviceID                    { get; set; }
        public bool     EmailAlertEnabled           { get; set; }
        public int      EmailAlertGroupingDelay     { get; set; }
        public bool     EmailAlertGroupingEnabled   { get; set; }
        public bool     EmailHtmlEnabled            { get; set; }
        public bool     IsVerified                  { get; set; }
        public bool     IsOwner                     { get; set; }
        public bool     IsProfessionalInstaller     { get; set; }
        public bool     IsSuperAdmin                { get; set; }
        public string   LastLoginIP                 { get; set; }
        public string   LastLoginTimestamp          { get; set; }
        public string   LastSiteName                { get; set; }
        public bool     PushAlertEnabled            { get; set; }
        public bool     RequiresNewPassword         { get; set; }
        public object   SuperSitePermissions        { get; set; }
        public object   Roles                       { get; set; }
        public object   SuperRoles                  { get; set; }
        public object   UISettings                  { get; set; }
        public object   TimeCreated                 { get; set; }
        public object   EncryptedPassword           { get; set; }

        public User() {}

        public User(object InputObject) {

            var psObjectType = InputObject.GetType();
            var propertiesProperty = psObjectType.GetProperty("Properties");
            var properties = propertiesProperty.GetValue(InputObject) as IEnumerable;

            foreach (var prop in properties) {
                var propType = prop.GetType();
                var name = propType.GetProperty("Name").GetValue(prop) as string;
                var value = propType.GetProperty("Value").GetValue(prop);

                switch (name) {
                    case "ID":
                    case "admin_id":
                    case "_id":
                        this.ID = value.ToString();
                        break;
                    
                    case "DeviceID":
                    case "device_id":
                        this.DeviceID = value.ToString();
                        break;
                    
                    case "Email":
                    case "email":
                        this.Email = value.ToString();
                        break;
                    
                    case "EmailAlertEnabled":
                    case "email_alert_enabled":
                        try {
                            this.EmailAlertEnabled = (bool)value;
                        } catch {
                            this.EmailAlertEnabled = true;
                        }
                        break;
                    
                    case "EmailAlertGroupingDelay":
                    case "email_alert_grouping_delay":
                        try {
                            this.EmailAlertGroupingDelay = (int)value;
                        } catch {
                            this.EmailAlertGroupingDelay = 60;
                        }
                        break;
                    
                    case "EmailAlertGroupingEnabled":
                    case "email_alert_grouping_enabled":
                        try {
                            this.EmailAlertGroupingEnabled = (bool)value;
                        } catch {
                            this.EmailAlertGroupingEnabled = true;
                        }
                        break;
                    
                    case "EmailHtmlEnabled":
                    case "html_email_enabled":
                        try {
                            this.EmailHtmlEnabled = (bool)value;
                        } catch {
                            this.EmailHtmlEnabled = true;
                        }
                        break;
                    
                    case "IsOwner":
                    case "is_owner":
                        try {
                            this.IsOwner = (bool)value;
                        } catch {
                            this.IsOwner = true;
                        }
                        break;
                    
                    case "IsVerified":
                    case "is_verified":
                        try {
                            this.IsVerified = (bool)value;
                        } catch {
                            this.IsVerified = true;
                        }
                        break;
                    
                    case "IsProfessionalInstaller":
                    case "is_professional_installer":
                        try {
                            this.IsProfessionalInstaller = (bool)value;
                        } catch {
                            this.IsProfessionalInstaller = true;
                        }
                        break;
                    
                    case "IsSuperAdmin":
                    case "is_super":
                        try {
                            this.IsSuperAdmin = (bool)value;
                        } catch {
                            this.IsSuperAdmin = true;
                        }
                        break;
                    
                    case "LastSiteName":
                    case "last_site_name":
                        this.LastSiteName = value.ToString();
                        break;
                    
                    case "Name":
                    case "name":
                        this.Name = value.ToString();
                        break;
                    
                    case "PushAlertEnabled":
                    case "push_alert_enabled":
                        try {
                            this.PushAlertEnabled = (bool)value;
                        } catch {
                            this.PushAlertEnabled = true;
                        }
                        break;
                    
                    case "RequiresNewPassword":
                    case "requires_new_password":
                        try {
                            this.RequiresNewPassword = (bool)value;
                        } catch {
                            this.RequiresNewPassword = true;
                        }
                        break;
                    
                    case "SuperSitePermissions":
                    case "super_site_permissions":
                        try {
                            this.SuperSitePermissions = value;
                        } catch {
                            this.SuperSitePermissions = null;
                        }
                        break;
                    
                    case "Roles":
                    case "roles":
                        try {
                            this.Roles = value;
                        } catch {
                            this.Roles = null;
                        }
                        break;
                    
                    case "SuperRoles":
                    case "super_roles":
                        try {
                            this.SuperRoles = value;
                        } catch {
                            this.SuperRoles = null;
                        }
                        break;
                    
                    case "UISettings":
                    case "ui_settings":
                        try {
                            this.UISettings = value;
                        } catch {
                            this.UISettings = null;
                        }
                        break;
                    
                    case "TimeCreated":
                    case "time_created":
                        this.TimeCreated = value.ToString();
                        break;
                    
                    case "LastLoginIP":
                    case "last_login_ip":
                        this.LastLoginIP = value.ToString();
                        break;
                    
                    case "LastLoginTimestamp":
                    case "last_login_timestamp":
                        this.LastLoginTimestamp = value.ToString();
                        break;
                    
                    case "EncryptedPassword":
                    case "x_shadow":
                        this.EncryptedPassword = value.ToString();
                        break;
                }
            }
        }
    }
}