using System;
using System.Collections;

namespace Unifi {
    public class Site {

        public string   AnonID          { get; set; }
        public string   ExternalID      { get; set; }
        public string   ID              { get; set; }
        public string   InternalName    { get; set; }
        public string   Name            { get; set; }
        public bool     Protected       { get; set; } = false;
        public Int64    DeviceCount     { get; set; }

        public Site() {}

        public Site(object InputObject) {

            var psObjectType = InputObject.GetType();
            var propertiesProperty = psObjectType.GetProperty("Properties");
            var properties = propertiesProperty.GetValue(InputObject) as IEnumerable;

            foreach (var prop in properties) {
                var propType = prop.GetType();
                var name = propType.GetProperty("Name").GetValue(prop) as string;
                var value = propType.GetProperty("Value").GetValue(prop);

                switch (name) {
                    case "AnonID":
                    case "anonymous_id":
                        this.AnonID = value.ToString();
                        break;

                    case "ExternalID":
                    case "external_id":
                        this.ExternalID = value.ToString();
                        break;

                    case "ID":
                    case "_id":
                        this.ID = value.ToString();
                        break;

                    case "InternalName":
                    case "name":
                        this.InternalName = value.ToString();
                        break;

                    case "Name":
                    case "desc":
                        this.Name = value.ToString();
                        break;

                    case "Protected":
                    case "attr_no_delete":
                        this.Protected = (bool)value;
                        break;

                    case "DeviceCount":
                    case "device_count":
                        this.DeviceCount = (Int64)value;
                        break;
                }
            }
        }
    }
}