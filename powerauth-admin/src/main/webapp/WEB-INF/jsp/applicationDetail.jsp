<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>

<jsp:include page="header.jsp">
    <jsp:param name="pageTitle" value="PowerAuth - Application Details"/>
</jsp:include>

<ol class="breadcrumb">
    <li><a class="black" href="${pageContext.request.contextPath}/application/list">Applications</a></li>
    <li class="active">Application Detail</li>
</ol>

<div class="row">

    <div class="col-md-12">
        <div class="panel panel-default">

            <div class="panel-heading">
                <h3 class="panel-title">Application: <c:out value="${id}"/></h3>
            </div>

            <div id="panel-with-tabs" class="panel-body">

                <ul class="nav nav-tabs" id="nav-tab" role="tablist">
                    <li role="presentation"><a href="#versions" id="tabs-versions" aria-controls="versions" role="tab" data-toggle="tab">Mobile App Config</a></li>
                    <li role="presentation"><a href="#callbacks" id="tabs-callbacks" aria-controls="callbacks" role="tab" data-toggle="tab">Callbacks</a></li>
                    <li role="presentation"><a href="#roles" id="tabs-roles" aria-controls="roles" role="tab" data-toggle="tab">Roles</a></li>
                </ul>

                <div id="tab-content" class="tab-content">

                    <div role="tabpanel" class="tab-pane" id="versions" aria-labelledby="tabs-versions">
                        <table class="table w100">
                            <tbody>
                            <tr>
                                <td>
                                    <div class="row">
                                        <div class="col-sm-12">
                                            <div class="panel panel-info" style="margin-top: 30px;">
                                                <div class="panel-body">
                                                    <span class="glyphicon glyphicon-info-sign"></span> Use the information below for PowerAuth Mobile SDK configuration.
                                                </div>
                                            </div>
                                        </div>

                                        <div class="col-sm-12">
                                            <div class="panel panel-default">
                                                <div class="panel-heading">
                                                    <h3 class="panel-title btn-sm pull-left">Application Versions</h3>
                                                    <a href="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/version/create" class="btn btn-sm btn-default pull-right">New Version</a>
                                                    <div class="clearfix"></div>
                                                </div>
                                                <div class="panel-body">
                                                    <table class="table">
                                                        <thead>
                                                        <tr>
                                                            <th>Version</th>
                                                            <th>Mobile SDK Config</th>
                                                            <th>Supported</th>
                                                            <th>Actions</th>
                                                        </tr>
                                                        </thead>
                                                        <tbody>
                                                        <c:forEach items="${versions}" var="item">
                                                            <tr class="code">
                                                                <td title="<c:out value="${item.applicationVersionId}"/>">
                                                                    <c:choose>
                                                                        <c:when test="${item.applicationVersionId.length() > 13}">
                                                                            <c:out value="${fn:substring(item.applicationVersionId, 0, 10)}"/>...
                                                                        </c:when>
                                                                        <c:otherwise>
                                                                            <c:out value="${item.applicationVersionId}"/>
                                                                        </c:otherwise>
                                                                    </c:choose>
                                                                </td>
                                                                <td>
                                                                    <c:out value="${fn:substring(item.mobileSdkConfig, 0, 50)}..."/>
                                                                    <button class="btn btn-default btn-table btn-clipboard" type="button" data-clipboard-text="<c:out value="${item.mobileSdkConfig}"/>">
                                                                        <span class="glyphicon glyphicon-copy"></span>
                                                                    </button>
                                                                </td>
                                                                <td>
                                                                    <c:choose>
                                                                        <c:when test="${item.supported}">
                                                                            <span>Yes</span>
                                                                        </c:when>
                                                                        <c:otherwise>
                                                                            <span>No</span>
                                                                        </c:otherwise>
                                                                    </c:choose>
                                                                </td>
                                                                <td>
                                                                    <c:choose>
                                                                        <c:when test="${item.supported}">
                                                                            <form action="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/version/update/do.submit" method="POST">
                                                                                <input type="hidden" name="enabled" value="false"/>
                                                                                <input type="hidden" name="version" value="<c:out value="${item.applicationVersionId}"/>"/>
                                                                                <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
                                                                                <input type="submit" value="Disable" class="btn btn-sm btn-danger btn-table"/>
                                                                            </form>
                                                                        </c:when>
                                                                        <c:otherwise>
                                                                            <form action="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/version/update/do.submit" method="POST">
                                                                                <input type="hidden" name="enabled" value="true"/>
                                                                                <input type="hidden" name="version" value="<c:out value="${item.applicationVersionId}"/>"/>
                                                                                <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
                                                                                <input type="submit" value="Enable" class="btn btn-sm btn-default btn-table"/>
                                                                            </form>
                                                                        </c:otherwise>
                                                                    </c:choose>
                                                                </td>
                                                            </tr>
                                                        </c:forEach>
                                                        </tbody>
                                                    </table>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                            </tr>
                            </tbody>
                        </table>
                    </div>

                    <div role="tabpanel" class="tab-pane" id="callbacks" aria-labelledby="tabs-callbacks">
                        <table class="table w100">
                            <tbody>
                            <tr>
                                <td>
                                    <div class="row">
                                        <div class="col-sm-12">
                                            <div class="panel panel-info" style="margin-top: 30px;">
                                                <div class="panel-body">
                                                    <span class="glyphicon glyphicon-info-sign"></span> Callbacks are URL addresses that are called whenever an activation status changes.
                                                </div>
                                            </div>
                                        </div>

                                        <div class="col-sm-12">

                                            <div class="panel panel-default">
                                                <div class="panel-heading">
                                                    <h3 class="panel-title button-sm pull-left">Callbacks</h3>
                                                    <a href="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/callback/create/form" class="btn btn-sm btn-default pull-right">Add Callback</a>
                                                    <div class="clearfix"></div>
                                                </div>

                                                <c:choose>
                                                    <c:when test="${fn:length(callbacks) == 0}">
                                                        <div class="panel-body">
                                                            <p class="gray text-center">
                                                                No callbacks are configured
                                                            </p>
                                                        </div>
                                                    </c:when>
                                                    <c:otherwise>
                                                        <table class="table">
                                                            <thead>
                                                            <tr>
                                                                <th>Name</th>
                                                                <th>Callback URL</th>
                                                                <th>&nbsp;</th>
                                                            </tr>
                                                            </thead>
                                                            <tbody>
                                                            <c:forEach items="${callbacks}" var="item">
                                                                <tr class="code" title="Callback ID: <c:out value="${item.id}"/>">
                                                                    <td><c:out value="${item.name}"/></td>
                                                                    <td><c:out value="${item.callbackUrl}"/></td>
                                                                    <td>
                                                                        <form action="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/callback/remove/do.submit" method="POST" class="pull-right action-remove">
                                                                            <input type="hidden" name="callbackId" value="<c:out value="${item.id}"/>"/>
                                                                            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
                                                                            <input type="submit" value="Remove" class="btn btn-sm btn-danger pull-right btn-table"/>
                                                                        </form>
                                                                        <form action="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/callback/update/form" method="GET" class="pull-right">
                                                                            <input type="hidden" name="callbackId" value="<c:out value="${item.id}"/>"/>
                                                                            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
                                                                            <input type="submit" value="Update" class="btn btn-sm btn-success pull-right btn-table"/>
                                                                        </form>
                                                                    </td>
                                                                </tr>
                                                            </c:forEach>
                                                            </tbody>
                                                        </table>
                                                    </c:otherwise>
                                                </c:choose>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                            </tr>
                            </tbody>
                        </table>
                    </div>

                    <div role="tabpanel" class="tab-pane" id="roles" aria-labelledby="tabs-roles">
                        <table class="table w100">
                            <tbody>
                            <tr>
                                <td>
                                    <div class="row">
                                        <div class="col-sm-12">
                                            <div class="panel panel-info" style="margin-top: 30px;">
                                                <div class="panel-body">
                                                    <span class="glyphicon glyphicon-info-sign"></span> Define roles
                                                    assigned to the application.
                                                </div>
                                            </div>
                                        </div>

                                        <div class="col-sm-12">
                                            <div class="panel panel-default">
                                                <div class="panel-heading">
                                                    <h3 class="panel-title btn-sm pull-left">Application Roles</h3>
                                                    <a href="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/role/create" class="btn btn-sm btn-default pull-right">Add Role</a>
                                                    <div class="clearfix"></div>
                                                </div>
                                                <c:choose>
                                                    <c:when test="${fn:length(roles) == 0}">
                                                        <div class="panel-body">
                                                            <p class="gray text-center">
                                                                No application roles are configured
                                                            </p>
                                                        </div>
                                                    </c:when>
                                                    <c:otherwise>
                                                        <table class="table">
                                                            <thead>
                                                            <tr>
                                                                <th>Role</th>
                                                                <th class="text-right">Actions</th>
                                                            </tr>
                                                            </thead>
                                                            <tbody>
                                                            <c:forEach items="${roles}" var="item">
                                                                <tr class="code">
                                                                    <td><c:out value="${item}"/></td>
                                                                    <td>
                                                                        <form action="${pageContext.request.contextPath}/application/detail/<c:out value="${id}"/>/role/remove/do.submit" method="POST" class="action-remove">
                                                                            <input type="hidden" name="name" value="${item}"/>
                                                                            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
                                                                            <input type="submit" value="Remove" class="btn btn-sm btn-danger pull-right btn-table"/>
                                                                        </form>
                                                                    </td>
                                                                </tr>
                                                            </c:forEach>
                                                            </tbody>
                                                        </table>
                                                    </c:otherwise>
                                                </c:choose>
                                            </div>
                                        </div>

                                    </div>
                                </td>
                            </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>

        </div>

    </div>

</div>

<jsp:include page="footer.jsp"/>

<script>
    $(document).ready(function (event) {
        // Choose tab by location hash
        if (!window.location.hash) {
            $('a[href="#versions"]').tab('show');
        } else {
            $('a[href="' + window.location.hash + '"]').tab('show');
        }
        // Change location hash on click
        $('.nav-tabs a').on('shown.bs.tab', function (e) {
            if (history.pushState) {
                history.pushState(null, null, e.target.hash);
            } else {
                window.location.hash = e.target.hash;
            }
        });
    });
</script>