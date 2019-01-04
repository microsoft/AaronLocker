using System;
using System.IO;
using System.Management.Automation;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

namespace AaronLocker
{
    /// <summary>
    /// Typeconverter that does the heavy lifting of maintaining type integrity across process borders.
    /// </summary>
    public class SerializationTypeConverter : PSTypeConverter
    {
        private static ResolveEventHandler AssemblyHandler = new ResolveEventHandler(SerializationTypeConverter.CurrentDomain_AssemblyResolve);

        /// <summary>
        /// Whether the source can be converted to its destination
        /// </summary>
        /// <param name="sourceValue">The value to convert</param>
        /// <param name="destinationType">The type to convert to</param>
        /// <returns>Whether this action is possible</returns>
        public override bool CanConvertFrom(object sourceValue, Type destinationType)
        {
            byte[] array;
            Exception ex;
            return this.CanConvert(sourceValue, destinationType, out array, out ex);
        }

        /// <summary>
        /// Converts an object
        /// </summary>
        /// <param name="sourceValue">The data to convert</param>
        /// <param name="destinationType">The type to convert to</param>
        /// <param name="formatProvider">This will be ignored, but must be present</param>
        /// <param name="ignoreCase">This will be ignored, but must be present</param>
        /// <returns>The converted object</returns>
        public override object ConvertFrom(object sourceValue, Type destinationType, IFormatProvider formatProvider, bool ignoreCase)
        {
            return this.DeserializeObject(sourceValue, destinationType);
        }

        /// <summary>
        /// Whether the input object can be converted to the Destination type
        /// </summary>
        /// <param name="sourceValue">Input value</param>
        /// <param name="destinationType">The type to convert to</param>
        /// <returns></returns>
        public override bool CanConvertTo(object sourceValue, Type destinationType)
        {
            byte[] array;
            Exception ex;
            return this.CanConvert(sourceValue, destinationType, out array, out ex);
        }

        /// <summary>
        /// Converts an object
        /// </summary>
        /// <param name="sourceValue">The data to convert</param>
        /// <param name="destinationType">The type to convert to</param>
        /// <param name="formatProvider">This will be ignored, but must be present</param>
        /// <param name="ignoreCase">This will be ignored, but must be present</param>
        /// <returns>The converted object</returns>
        public override object ConvertTo(object sourceValue, Type destinationType, IFormatProvider formatProvider, bool ignoreCase)
        {
            return this.DeserializeObject(sourceValue, destinationType);
        }
        private bool CanConvert(object sourceValue, Type destinationType, out byte[] serializationData, out Exception error)
        {
            serializationData = null;
            error = null;
            if (destinationType == null)
            {
                error = new ArgumentNullException("destinationType");
                return false;
            }
            if (sourceValue == null)
            {
                error = new ArgumentNullException("sourceValue");
                return false;
            }
            PSObject pSObject = sourceValue as PSObject;
            if (pSObject == null)
            {
                error = new NotSupportedException(string.Format("Unsupported Source Type: {0}", sourceValue.GetType().FullName));
                return false;
            }
            if (!SerializationTypeConverter.CanSerialize(destinationType))
            {
                error = new NotSupportedException(string.Format("Unsupported Type Conversion: {0}", destinationType.FullName));
                return false;
            }
            if (typeof(Exception).IsAssignableFrom(destinationType) && pSObject.TypeNames != null && pSObject.TypeNames.Count > 0 && pSObject.TypeNames[0].StartsWith("Deserialized.System.Management.Automation"))
            {
                foreach (string current in pSObject.TypeNames)
                {
                    if (current.Equals("Deserialized.System.Management.Automation.ParameterBindingException", StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
            }
            if (pSObject.Properties["SerializationData"] == null)
            {
                error = new NotSupportedException("Serialization Data is Absent");
                return false;
            }
            object value = pSObject.Properties["SerializationData"].Value;
            if (!(value is byte[]))
            {
                error = new NotSupportedException("Unsupported Data Format");
                return false;
            }
            serializationData = (value as byte[]);
            return true;
        }
        private object DeserializeObject(object sourceValue, Type destinationType)
        {
            byte[] buffer;
            Exception ex;
            if (!this.CanConvert(sourceValue, destinationType, out buffer, out ex))
            {
                throw ex;
            }
            object obj;
            using (MemoryStream memoryStream = new MemoryStream(buffer))
            {
                AppDomain.CurrentDomain.AssemblyResolve += SerializationTypeConverter.AssemblyHandler;
                try
                {
                    BinaryFormatter binaryFormatter = new BinaryFormatter();
                    obj = binaryFormatter.Deserialize(memoryStream);
                    IDeserializationCallback deserializationCallback = obj as IDeserializationCallback;
                    if (deserializationCallback != null)
                    {
                        deserializationCallback.OnDeserialization(sourceValue);
                    }
                }
                finally
                {
                    AppDomain.CurrentDomain.AssemblyResolve -= SerializationTypeConverter.AssemblyHandler;
                }
            }
            return obj;
        }

        /// <summary>
        /// Registers an assembly resolving event
        /// </summary>
        public static void RegisterAssemblyResolver()
        {
            AppDomain.CurrentDomain.AssemblyResolve += SerializationTypeConverter.AssemblyHandler;
        }
        private static System.Reflection.Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
        {
            System.Reflection.Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
            for (int i = 0; i < assemblies.Length; i++)
            {
                if (assemblies[i].FullName == args.Name)
                {
                    return assemblies[i];
                }
            }
            return null;
        }

        /// <summary>
        /// Whether an object can be serialized
        /// </summary>
        /// <param name="obj">The object to test</param>
        /// <returns>Whether the object can be serialized</returns>
        public static bool CanSerialize(object obj)
        {
            return obj != null && SerializationTypeConverter.CanSerialize(obj.GetType());
        }

        /// <summary>
        /// Whether a type can be serialized
        /// </summary>
        /// <param name="type">The type to test</param>
        /// <returns>Whether the specified type can be serialized</returns>
        public static bool CanSerialize(Type type)
        {
            return SerializationTypeConverter.TypeIsSerializable(type) && !type.IsEnum || (type.Equals(typeof(Exception)) || type.IsSubclassOf(typeof(Exception)));
        }

        /// <summary>
        /// The validation check on whether a type is serializable
        /// </summary>
        /// <param name="type">The type to test</param>
        /// <returns>Returns whether that type can be serialized</returns>
        public static bool TypeIsSerializable(Type type)
        {
            if (type == null)
            {
                throw new ArgumentNullException("type");
            }
            if (!type.IsSerializable)
            {
                return false;
            }
            if (!type.IsGenericType)
            {
                return true;
            }
            Type[] genericArguments = type.GetGenericArguments();
            for (int i = 0; i < genericArguments.Length; i++)
            {
                Type type2 = genericArguments[i];
                if (!SerializationTypeConverter.TypeIsSerializable(type2))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Used to obtain the information to write
        /// </summary>
        /// <param name="psObject">The object to dissect</param>
        /// <returns>A memory stream.</returns>
        public static object GetSerializationData(PSObject psObject)
        {
            object result;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                BinaryFormatter binaryFormatter = new BinaryFormatter();
                binaryFormatter.Serialize(memoryStream, psObject.BaseObject);
                result = memoryStream.ToArray();
            }
            return result;
        }
    }
}