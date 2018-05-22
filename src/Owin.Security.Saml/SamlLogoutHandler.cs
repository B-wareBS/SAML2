using Microsoft.Owin;
using Owin.Security.Saml.Notifications;
using SAML2;
using SAML2.Bindings;
using SAML2.Logging;
using SAML2.Protocol;
using SAML2.Schema.Protocol;
using SAML2.Utils;
using System;
using System.Collections.Specialized;
using System.IO;
using System.Threading.Tasks;
using System.Xml;

namespace Owin.Security.Saml
{
    public class SamlLogoutHandler : SamlAbstractEndpointHandler
    {
        private static readonly IInternalLogger Logger = LoggerProvider.LoggerFor(typeof(SamlLogoutHandler));

        private readonly SamlAuthenticationOptions options;

        public SamlLogoutHandler(SamlAuthenticationOptions options)
            : base(options.Configuration)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            this.options = options;
        }

        public async Task<bool> Invoke(IOwinContext context)
        {
            Logger.Debug(TraceMessages.LogoutHandlerCalled);

            var requestParams = context.Request.GetRequestParameters().ToNameValueCollection();

            // Some IDP's are known to fail to set an actual value in the SOAPAction header
            // so we just check for the existence of the header field.
            // and some servers don't send SOAP headers at all so fix those:
            if (context.Request.Headers.ContainsKey(SoapConstants.SoapAction)
                || "text/xml".Equals(context.Request.ContentType, StringComparison.OrdinalIgnoreCase))
            {
                await HandleSoap(context, context.Request.Body, requestParams);
                return await Task.FromResult(true);
            }

            //if (!string.IsNullOrEmpty(requestParams["SAMLart"]))
            //{
            //    HandleArtifact(context, ConfigurationFactory.Instance.Configuration, HandleSoap);
            //    return;
            //}

            if (!string.IsNullOrEmpty(requestParams["SAMLResponse"]))
            {
                try
                {
                    HandleResponse(context, requestParams);
                }
                catch (Exception ex)
                {
                    throw new SamlEndpointException("Error during logout request, see inner exception", ex);
                }

                return await Task.FromResult(true);
            }
            //else if (!string.IsNullOrEmpty(context.Request.Params["SAMLRequest"]))
            //{
            //    HandleRequest(context);
            //}
            //else
            //{
            //    IdentityProvider idpEndpoint = null;

            //    // context.Session[IDPLoginSessionKey] may be null if IIS has been restarted
            //    if (context.Session[IdpSessionIdKey] != null)
            //    {
            //        idpEndpoint = IdpSelectionUtil.RetrieveIDPConfiguration((string)context.Session[IdpLoginSessionKey], config);
            //    }

            //    if (idpEndpoint == null)
            //    {
            //        // TODO: Reconsider how to accomplish this.
            //        context.User = null;
            //        FormsAuthentication.SignOut();

            //        Logger.ErrorFormat(ErrorMessages.UnknownIdentityProvider, string.Empty);
            //        throw new Saml20Exception(string.Format(ErrorMessages.UnknownIdentityProvider, string.Empty));
            //    }

            //    TransferClient(idpEndpoint, context, config);
            //}

            throw new NotImplementedException();
        }

        /// <summary>
        /// Handles the response.
        /// </summary>
        /// <param name="context">The context.</param>
        private void HandleResponse(IOwinContext context, NameValueCollection requestParams)
        {
            var requestType = context.Request.Method;
            var requestUrl = context.Request.Uri;
            new Logout(Logger, options.Configuration).ValidateLogoutRequest(requestType, requestParams, requestUrl);
            // Log the user out locally
            DoLogout(context, false);

            // maybe possible from relay state if not set here
            context.Response.Redirect(options.RedirectAfterLogoff ?? "/");
        }

        /// <summary>
        /// Handles executing the logout.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="idpInitiated">if set to <c>true</c> identity provider is initiated.</param>
        private void DoLogout(IOwinContext context, bool idpInitiated = false)
        {
            Logger.Debug(TraceMessages.LogoutActionsExecuting);
            // TODO: Event for logout actions
            //foreach (var action in Actions.Actions.GetActions(config))
            //{
            //    Logger.DebugFormat("{0}.{1} called", action.GetType(), "LogoutAction()");

            //    action.LogoutAction(this, context, idpInitiated);

            //    Logger.DebugFormat("{0}.{1} finished", action.GetType(), "LogoutAction()");
            //}
        }

        /// <summary>
        /// Handles the SOAP message.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="inputStream">The input stream.</param>
        private async Task HandleSoap(IOwinContext context, Stream inputStream, NameValueCollection requestParams)
        {
            var config = options.Configuration;

            var parser = new HttpArtifactBindingParser(inputStream);
            Logger.DebugFormat(TraceMessages.SOAPMessageParse, parser.SamlMessage.OuterXml);

            var builder = GetBuilder(context);
            var idp = IdpSelectionUtil.RetrieveIDPConfiguration(parser.Issuer, config);

            if (parser.IsLogoutReqest)
            {
                Logger.DebugFormat(TraceMessages.LogoutRequestReceived, parser.SamlMessage.OuterXml);

                if (!parser.CheckSamlMessageSignature(idp.Metadata.Keys))
                {
                    Logger.ErrorFormat(ErrorMessages.ArtifactResolveSignatureInvalid);
                    throw new Saml20Exception(ErrorMessages.ArtifactResolveSignatureInvalid);
                }

                var req = parser.LogoutRequest;

                var logoutRequestReceivedNotification = new LogoutRequestReceivedNotification<LogoutRequest, SamlAuthenticationOptions>(context, options)
                {
                    ProtocolMessage = req
                };

                await options.Notifications.LogoutRequestReceived(logoutRequestReceivedNotification);

                DoLogout(context, true);

                // Build the response object
                var response = new Saml20LogoutResponse
                {
                    Issuer = config.ServiceProvider.Id,
                    StatusCode = Saml20Constants.StatusCodes.Success,
                    InResponseTo = req.Id
                };

                // response.Destination = destination.Url;
                var doc = response.GetXml();
                XmlSignatureUtils.SignDocument(doc, response.Id, config.ServiceProvider.SigningCertificate);
                if (doc.FirstChild is XmlDeclaration)
                {
                    doc.RemoveChild(doc.FirstChild);
                }

                SendResponseMessage(doc.OuterXml, context);
            }
            else
            {
                Logger.ErrorFormat(ErrorMessages.SOAPMessageUnsupportedSamlMessage);
                throw new Saml20Exception(ErrorMessages.SOAPMessageUnsupportedSamlMessage);
            }
        }
    }
}
