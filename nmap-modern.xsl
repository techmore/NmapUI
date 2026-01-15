<?xml version="1.0" encoding="utf-8"?>
<!--
Nmap Modern XSL
Updated with modern Tailwind styling and olive color scheme
This software must not be used by military or secret service organisations.
Original: Andreas Hontzia (@honze_net) & LRVT (@l4rm4nd)
Updated: 2026
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="utf-8" indent="yes" doctype-system="about:legacy-compat"/>

  <xsl:param name="techmore_version"/>

   <!-- Services that have both product and version -->
  <xsl:key name="svcByProduct"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="@product"/>

  <!-- Distinct Product|Version groups -->
  <xsl:key name="svcByProdVer"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="concat(@product,'|',@version)"/>

  <!-- Distinct Product|Version|Host groups (for unique host counting) -->
  <xsl:key name="svcByProdVerHost"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="concat(@product,'|',@version,'|', ancestor::host/address/@addr)"/>

  <!-- Distinct Product|Version|Host|Port groups (for host list with ports) -->
  <xsl:key name="svcByProdVerHostPort"
           match="nmaprun/host/ports/port[state/@state='open']/service[@product and @version]"
           use="concat(@product,'|',@version,'|',
                       ancestor::host/address/@addr,'|',
                       ../@protocol,'|',../@portid)"/>
  
  <!-- All open SSH services (name="ssh") -->
  <xsl:key name="sshSvcs"
           match="nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']"
           use="1"/>

  <!-- Product|Version groups derived from HTTP titles like 'Apache Tomcat/7.0.54' -->
  <xsl:key name="httpTitleByProdVer"
           match="nmaprun/host/ports/port[state/@state='open' and @protocol='tcp']
                  /script[@id='http-title']/elem[@key='title'][contains(normalize-space(.), '/')]"
           use="concat(
                  substring-before(normalize-space(.), '/'),
                  '|',
                  substring-after(normalize-space(.), '/')
               )"/>

  <!-- Distinct Product|Version|Host|Port groups for HTTP-title based entries -->
  <xsl:key name="httpTitleByProdVerHostPort"
           match="nmaprun/host/ports/port[state/@state='open' and @protocol='tcp']
                  /script[@id='http-title']/elem[@key='title'][contains(normalize-space(.), '/')]"
           use="concat(
                  substring-before(normalize-space(.), '/'),
                  '|',
                  substring-after(normalize-space(.), '/'),
                  '|',
                  ancestor::host/address/@addr,
                  '|',
                  ancestor::port[1]/@protocol,
                  '|',
                  ancestor::port[1]/@portid
               )"/>           

  <xsl:template match="/">
    <html lang="en">
      <head>
        <meta name="referrer" content="no-referrer"/>
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="preconnect" href="https://fonts.googleapis.com"/>
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin=""/>
        <link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&amp;family=Inter:wght@300;400;500;600;700&amp;display=swap" rel="stylesheet"/>
        
        <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css"/>
        <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.dataTables.min.css"/>
        
        <script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha384-1H217gwSVyLSIfaLxHbE7dRb3v4mYCKbpQvzx0cegeju1MVsGrX5xXxAvs/HgeFs" crossorigin="anonymous"></script>
        <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.js"></script>
        <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
        <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
        <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.colVis.min.js"></script>
        <script src="https://cdn.datatables.net/plug-ins/1.13.7/sorting/ip-address.js"></script>
        
        <script>
          tailwind.config = {
            theme: {
              extend: {
                colors: {
                  olive: {
                    50: '#f5f6f3',
                    100: '#e9ebe0',
                    200: '#d8dbc7',
                    300: '#bcc2a9',
                    400: '#979f83',
                    500: '#777f65',
                    600: '#636b54',
                    700: '#525845',
                    800: '#414637',
                    900: '#32382a',
                    950: '#25291f',
                  }
                },
                fontFamily: {
                  display: ['Instrument Serif', 'serif'],
                  sans: ['Inter', 'system-ui', 'sans-serif'],
                }
              }
            }
          }
        </script>
        
        <style>
          body {
            font-family: 'Inter', system-ui, sans-serif;
            background-color: #e9ebe0;
            color: #262724;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
          }
          
          h1, h2, h3, h4, h5 {
            font-family: 'Instrument Serif', serif;
          }
          
          ::selection {
            background-color: #bcc2a9;
            color: white;
          }
          
          .nav-link {
            position: relative;
            transition: color 0.2s ease;
          }
          
          .nav-link:hover {
            color: #636b54;
          }
          
          .nav-link::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 0;
            height: 2px;
            background-color: #636b54;
            transition: width 0.2s ease;
          }
          
          .nav-link:hover::after {
            width: 100%;
          }
          
          .card {
            background: white;
            border: 1px solid #d8dbc7;
            border-radius: 12px;
            transition: all 0.2s ease;
          }
          
          .card:hover {
            border-color: #bcc2a9;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
          }
          
          .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 500;
          }
          
          .badge-success {
            background-color: #979f83;
            color: white;
          }
          
          .badge-danger {
            background-color: #ef4444;
            color: white;
          }
          
          .badge-warning {
            background-color: #f59e0b;
            color: white;
          }
          
          table.dataTable {
            border-collapse: separate;
            border-spacing: 0;
            border: 1px solid #d8dbc7;
            border-radius: 12px;
            overflow: hidden;
          }
          
          table.dataTable thead th {
            background-color: #32382a;
            color: white;
            font-weight: 500;
            border: none;
            padding: 12px 16px;
          }
          
          table.dataTable tbody td {
            border-top: 1px solid #d8dbc7;
            padding: 12px 16px;
          }
          
          table.dataTable tbody tr:hover {
            background-color: #f5f6f3;
          }
          
          .dt-buttons {
            margin-bottom: 16px;
          }
          
          .dt-button {
            background-color: #32382a !important;
            color: white !important;
            border: none !important;
            padding: 8px 16px !important;
            border-radius: 8px !important;
            margin-right: 8px !important;
            font-size: 0.875rem !important;
            transition: background-color 0.2s ease !important;
          }
          
          .dt-button:hover {
            background-color: #525845 !important;
          }
          
          input[type="text"],
          input[type="search"],
          textarea {
            background-color: white;
            color: #25291f;
            border: 1px solid #bcc2a9;
            padding: 8px 12px;
            border-radius: 8px;
            outline: none;
            transition: border-color 0.2s ease;
          }
          
          input:focus,
          textarea:focus {
            border-color: #636b54;
          }
          
          button {
            background-color: #32382a;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.2s ease;
            font-weight: 500;
          }
          
          button:hover {
            background-color: #525845;
          }
          
          pre {
            background-color: #f5f6f3;
            border: 1px solid #d8dbc7;
            border-radius: 8px;
            padding: 16px;
            overflow-x: auto;
          }
          
          a {
            color: #636b54;
            text-decoration: none;
            transition: color 0.2s ease;
          }
          
          a:hover {
            color: #525845;
            text-decoration: underline;
          }
          
          .progress-bar {
            height: 32px;
            background-color: #f5f6f3;
            border-radius: 9999px;
            overflow: hidden;
            display: flex;
          }
          
          .progress-segment {
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 500;
            font-size: 0.875rem;
            transition: width 0.3s ease;
          }
          
          .progress-success {
            background-color: #979f83;
          }
          
          .progress-danger {
            background-color: #ef4444;
          }
          
          .highlight-keyword {
            color: #ef4444;
            font-weight: 600;
          }
          
          .collapsible-header {
            cursor: pointer;
            user-select: none;
          }
          
          .collapsible-header:hover {
            background-color: #f5f6f3;
          }
          
          .chevron {
            transition: transform 0.2s ease;
          }
          
          .chevron.collapsed {
            transform: rotate(-90deg);
          }
          
          @keyframes fadeIn {
            from {
              opacity: 0;
              transform: translateY(10px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }
          
          .fade-in {
            animation: fadeIn 0.3s ease;
          }

          @media print {
            /* Force background colors to print in PDF */
            body {
              background-color: #e9ebe0 !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            /* Ensure cards have white background */
            .card {
              background: white !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            /* Ensure table headers have background color */
            table.dataTable thead th {
              background-color: #32382a !important;
              color: white !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            /* Ensure badges have background colors */
            .badge-success {
              background-color: #979f83 !important;
              color: white !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            .badge-danger {
              background-color: #ef4444 !important;
              color: white !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            .badge-warning {
              background-color: #f59e0b !important;
              color: white !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            /* Ensure progress segments have background colors */
            .progress-success {
              background-color: #979f83 !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            .progress-danger {
              background-color: #ef4444 !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            /* Hide navigation, buttons, and interactive elements */
            nav,
            .dt-buttons,
            .dataTables_paginate,
            .dataTables_length,
            .dataTables_filter,
            .collapsible-header,
            button,
            input,
            textarea {
              display: none !important;
            }

            /* Show all collapsible content */
            [id^="content-"] {
              display: block !important;
            }

            /* Ensure pre blocks have background */
            pre {
              background-color: #f5f6f3 !important;
              -webkit-print-color-adjust: exact !important;
              print-color-adjust: exact !important;
            }

            /* Add page breaks between major sections */
            #scannedhosts,
            #openservices,
            #webservices,
            #productversions,
            #ssh-auth,
            #onlinehosts {
              page-break-after: always;
            }

            /* Avoid page breaks inside cards */
            .card {
              page-break-inside: avoid;
            }

            /* Adjust margins for print */
            @page {
              margin: 10mm;
            }
          }
        </style>

        <title>Nmap Scan Results</title>
      </head>
      
      <body class="min-h-screen">
        <!-- Fixed Navigation -->
        <nav class="fixed top-0 left-0 right-0 bg-white border-b border-olive-200 z-50 shadow-sm">
          <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
              <div class="flex items-center space-x-8">
                <span class="text-2xl font-display font-semibold text-olive-900">Nmap Results</span>
                <div class="hidden md:flex space-x-6">
                  <a href="#scannedhosts" class="nav-link text-sm font-medium text-olive-700">Scanned Hosts</a>
                  <a href="#openservices" class="nav-link text-sm font-medium text-olive-700">Open Services</a>
                  <a href="#webservices" class="nav-link text-sm font-medium text-olive-700">Web Services</a>
                  <a href="#productversions" class="nav-link text-sm font-medium text-olive-700">Product Versions</a>
                  <xsl:if test="count(/nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']) &gt; 0">
                    <a href="#ssh-auth" class="nav-link text-sm font-medium text-olive-700">SSH Auth</a>
                  </xsl:if>
                  <a href="#onlinehosts" class="nav-link text-sm font-medium text-olive-700">Online Hosts</a>
                </div>
              </div>
              <div class="flex items-center space-x-4">
                <a href="https://www.pentestfactory.de/schwachstellendatenbank/" target="_blank" 
                   class="text-sm text-olive-600 hover:text-olive-800" title="Vulnerability Database">CVEs ↗</a>
                <a href="https://www.ssllabs.com/ssltest/" target="_blank" 
                   class="text-sm text-olive-600 hover:text-olive-800" title="SSL Server Test">SSL/TLS ↗</a>
                <a href="https://securityheaders.com/" target="_blank" 
                   class="text-sm text-olive-600 hover:text-olive-800" title="HTTP Header Test">Headers ↗</a>
              </div>
            </div>
          </div>
        </nav>

        <!-- Main Content -->
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-24 pb-12">
          
          <!-- Hero Section -->
          <div class="card p-8 mb-8 fade-in">
            <h1 class="text-4xl font-display font-bold text-olive-900 mb-2">Nmap Port Scanning Results</h1>
            <p class="text-sm text-olive-500 mb-1">
              Techmore Network Scanner <xsl:value-of select="$techmore_version"/>
            </p>
            <p class="text-olive-600 mb-4">
              Version <xsl:value-of select="/nmaprun/@version"/> ·
              <xsl:value-of select="/nmaprun/@startstr"/> – <xsl:value-of select="/nmaprun/runstats/finished/@timestr"/>
            </p>
            
            <div class="bg-olive-50 border border-olive-200 rounded-lg p-4 mb-6">
              <pre class="text-xs overflow-x-auto"><a target="_blank" class="text-olive-700 hover:text-olive-900"><xsl:attribute name="href">https://explainshell.com/explain?cmd=<xsl:value-of select="/nmaprun/@args"/></xsl:attribute><xsl:value-of select="/nmaprun/@args"/></a></pre>
            </div>
            
            <div class="grid grid-cols-3 gap-4 mb-6">
              <div class="text-center">
                <div class="text-3xl font-bold text-olive-900"><xsl:value-of select="/nmaprun/runstats/hosts/@total"/></div>
                <div class="text-sm text-olive-600">Total IPs Scanned</div>
              </div>
              <div class="text-center">
                <div class="text-3xl font-bold text-olive-600"><xsl:value-of select="/nmaprun/runstats/hosts/@up"/></div>
                <div class="text-sm text-olive-600">Hosts Online</div>
              </div>
              <div class="text-center">
                <div class="text-3xl font-bold text-olive-400"><xsl:value-of select="/nmaprun/runstats/hosts/@down"/></div>
                <div class="text-sm text-olive-600">Hosts Offline</div>
              </div>
            </div>

            <!-- Enhanced Summary Dashboard -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
              <!-- Critical Vulnerabilities -->
              <div class="card p-4">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="w-8 h-8 bg-red-100 rounded-full flex items-center justify-center">
                      <span class="text-red-600 font-bold text-sm">!</span>
                    </div>
                  </div>
                  <div class="ml-3">
                    <div class="text-2xl font-bold text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/script[@id='vulners'][contains(@output, '9.') or contains(@output, '10.')])"/>
                    </div>
                    <div class="text-sm text-olive-600">Critical Vulns (CVSS ≥9.0)</div>
                  </div>
                </div>
              </div>

              <!-- Device Types -->
              <div class="card p-4">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="w-8 h-8 bg-olive-100 rounded-full flex items-center justify-center">
                      <span class="text-olive-600 font-bold text-sm">🖥️</span>
                    </div>
                  </div>
                  <div class="ml-3">
                    <div class="text-2xl font-bold text-olive-700">
                      <xsl:value-of select="count(/nmaprun/host[os/osmatch/@name])"/>
                    </div>
                    <div class="text-sm text-olive-600">OS Identified</div>
                  </div>
                </div>
              </div>

              <!-- Open Ports -->
              <div class="card p-4">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                      <span class="text-blue-600 font-bold text-sm">🔓</span>
                    </div>
                  </div>
                  <div class="ml-3">
                    <div class="text-2xl font-bold text-blue-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open'])"/>
                    </div>
                    <div class="text-sm text-olive-600">Total Open Ports</div>
                  </div>
                </div>
              </div>

              <!-- Web Services -->
              <div class="card p-4">
                <div class="flex items-center">
                  <div class="flex-shrink-0">
                    <div class="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center">
                      <span class="text-green-600 font-bold text-sm">🌐</span>
                    </div>
                  </div>
                  <div class="ml-3">
                    <div class="text-2xl font-bold text-green-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and (service/@name='http' or service/@name='https' or service/@tunnel='ssl')])"/>
                    </div>
                    <div class="text-sm text-olive-600">Web Services</div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Network & Vulnerability Summary -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
              <!-- Network Range -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Network Scanned</h3>
                <div class="space-y-1">
                  <div class="text-sm text-olive-700">
                    <span class="font-medium">Target:</span>
                    <xsl:value-of select="substring-after(/nmaprun/@args, ' ')"/>
                  </div>
                  <div class="text-sm text-olive-700">
                    <span class="font-medium">IPs:</span> <xsl:value-of select="/nmaprun/runstats/hosts/@total"/>
                  </div>
                  <div class="text-sm text-olive-700">
                    <span class="font-medium">Started:</span> <xsl:value-of select="/nmaprun/@startstr"/>
                  </div>
                  <div class="text-sm text-olive-700">
                    <span class="font-medium">Duration:</span>
                    <xsl:value-of select="/nmaprun/runstats/finished/@elapsed"/>s
                  </div>
                </div>
              </div>

              <!-- Vulnerability Severity -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Vulnerability Levels</h3>
                <div class="space-y-2">
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-red-600 font-medium">Critical (CVSS ≥9.0)</span>
                    <span class="text-sm font-bold text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/script[@id='vulners'][contains(@output, '9.') or contains(@output, '10.')])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-orange-600 font-medium">High (CVSS ≥7.0)</span>
                    <span class="text-sm font-bold text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host/script[@id='vulners'][contains(@output, '7.') or contains(@output, '8.')])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-yellow-600 font-medium">Medium (CVSS ≥4.0)</span>
                    <span class="text-sm font-bold text-yellow-600">
                      <xsl:value-of select="count(/nmaprun/host/script[@id='vulners'][contains(@output, '4.') or contains(@output, '5.') or contains(@output, '6.')])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-green-600 font-medium">Low (CVSS &lt;4.0)</span>
                    <span class="text-sm font-bold text-green-600">
                      <xsl:value-of select="count(/nmaprun/host/script[@id='vulners'][contains(@output, '0.') or contains(@output, '1.') or contains(@output, '2.') or contains(@output, '3.')])"/>
                    </span>
                  </div>
                </div>
              </div>

              <!-- Device Vendors -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Top Vendors</h3>
                <div class="space-y-2">
                  <xsl:for-each select="/nmaprun/host/address[@addrtype='mac']/@vendor[not(. = preceding::address/@vendor)]">
                    <xsl:sort select="count(/nmaprun/host[address[@addrtype='mac' and @vendor=current()]])" data-type="number" order="descending"/>
                    <xsl:if test="position() &lt;= 5 and string-length(.) > 0">
                      <div class="flex justify-between items-center">
                        <span class="text-sm text-olive-700 truncate max-w-xs" title="{.}">
                          <xsl:value-of select="substring(., 1, 25)"/>
                          <xsl:if test="string-length(.) > 25">...</xsl:if>
                        </span>
                        <span class="text-sm font-medium text-olive-900 ml-2">
                          <xsl:value-of select="count(/nmaprun/host[address[@addrtype='mac' and @vendor=current()]])"/>
                        </span>
                      </div>
                    </xsl:if>
                  </xsl:for-each>
                </div>
              </div>
            </div>

            <!-- Security Risk Assessment -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              <!-- High-Risk Services -->
              <div class="card p-4 border-l-4 border-red-400">
                <h3 class="text-lg font-semibold text-olive-900 mb-3 flex items-center">
                  <span class="w-3 h-3 bg-red-500 rounded-full mr-2"></span>
                  High-Risk Services
                </h3>
                <div class="space-y-2">
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">SSH Servers</span>
                    <span class="text-sm font-medium text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and service/@name='ssh'])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Remote Desktop</span>
                    <span class="text-sm font-medium text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and (service/@name='rdp' or service/@name='ms-wbt-server')])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">SMB/File Shares</span>
                    <span class="text-sm font-medium text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and (service/@name='netbios-ssn' or service/@name='microsoft-ds')])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Telnet (Unencrypted)</span>
                    <span class="text-sm font-medium text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and service/@name='telnet'])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">FTP (Unencrypted)</span>
                    <span class="text-sm font-medium text-red-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and service/@name='ftp'])"/>
                    </span>
                  </div>
                </div>
              </div>

              <!-- Compliance & Security Issues -->
              <div class="card p-4 border-l-4 border-orange-400">
                <h3 class="text-lg font-semibold text-olive-900 mb-3 flex items-center">
                  <span class="w-3 h-3 bg-orange-500 rounded-full mr-2"></span>
                  Security Issues
                </h3>
                <div class="space-y-2">
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Default HTTP Ports</span>
                    <span class="text-sm font-medium text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and @portid='80' and service/@name='http' and not(service/@tunnel='ssl')])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Hosts with >10 Open Ports</span>
                    <span class="text-sm font-medium text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host[count(ports/port[state/@state='open']) > 10])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Unknown Services</span>
                    <span class="text-sm font-medium text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and service/@name='unknown'])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Outdated SSL/TLS</span>
                    <span class="text-sm font-medium text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[script[@id='ssl-enum-ciphers'] and script/elem[contains(text(), 'SSLv3') or contains(text(), 'TLSv1.0') or contains(text(), 'TLSv1.1')]])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Hosts Without Hostnames</span>
                    <span class="text-sm font-medium text-orange-600">
                      <xsl:value-of select="count(/nmaprun/host[not(hostnames/hostname/@name) or hostnames/hostname/@name=''])"/>
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <!-- Top 10 Most Vulnerable & Most Open Ports -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              <!-- Hosts with Vulnerabilities -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Hosts with Vulnerabilities</h3>
                <div class="space-y-2 max-h-64 overflow-y-auto">
                  <xsl:for-each select="/nmaprun/host[script[@id='vulners']]">
                    <xsl:if test="position() &lt;= 10">
                      <div class="flex justify-between items-center py-1">
                        <span class="text-sm font-mono text-olive-700">
                          <xsl:value-of select="address/@addr"/>
                        </span>
                        <span class="text-sm font-medium text-red-600 bg-red-50 px-2 py-1 rounded">
                          <xsl:if test="contains(script[@id='vulners']/@output, '9.') or contains(script[@id='vulners']/@output, '10.')">
                            Critical
                          </xsl:if>
                          <xsl:if test="contains(script[@id='vulners']/@output, '7.') or contains(script[@id='vulners']/@output, '8.')">
                            High
                          </xsl:if>
                        </span>
                      </div>
                    </xsl:if>
                  </xsl:for-each>
                </div>
              </div>

              <!-- Hosts with Most Open Ports -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Most Open Ports</h3>
                <div class="space-y-2 max-h-64 overflow-y-auto">
                  <xsl:for-each select="/nmaprun/host">
                    <xsl:sort select="count(ports/port[state/@state='open'])" data-type="number" order="descending"/>
                    <xsl:if test="position() &lt;= 10 and count(ports/port[state/@state='open']) > 0">
                      <div class="flex justify-between items-center py-1">
                        <span class="text-sm font-mono text-olive-700">
                          <xsl:value-of select="address/@addr"/>
                        </span>
                        <span class="text-sm font-medium text-blue-600 bg-blue-50 px-2 py-1 rounded">
                          <xsl:value-of select="count(ports/port[state/@state='open'])"/> ports
                        </span>
                      </div>
                    </xsl:if>
                  </xsl:for-each>
                </div>
              </div>
            </div>

            <!-- Network Health & Performance -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
              <!-- Network Utilization -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Network Utilization</h3>
                <div class="space-y-3">
                  <div>
                    <div class="flex justify-between text-sm mb-1">
                      <span class="text-olive-700">IP Space Used</span>
                      <span class="font-medium text-olive-900">
                        <xsl:value-of select="format-number(/nmaprun/runstats/hosts/@up div /nmaprun/runstats/hosts/@total * 100, '0.1')"/>%
                      </span>
                    </div>
                    <div class="w-full bg-olive-200 rounded-full h-2">
                      <div class="bg-olive-600 h-2 rounded-full">
                        <xsl:attribute name="style">width: <xsl:value-of select="/nmaprun/runstats/hosts/@up div /nmaprun/runstats/hosts/@total * 100"/>%</xsl:attribute>
                      </div>
                    </div>
                  </div>
                  <div class="text-xs text-olive-600">
                    <xsl:value-of select="/nmaprun/runstats/hosts/@up"/> of <xsl:value-of select="/nmaprun/runstats/hosts/@total"/> IPs responding
                  </div>
                </div>
              </div>

              <!-- Scan Performance -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Scan Performance</h3>
                <div class="space-y-2">
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Duration</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="/nmaprun/runstats/finished/@elapsed"/>s
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Avg per Host</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="format-number(/nmaprun/runstats/finished/@elapsed div /nmaprun/runstats/hosts/@total, '0.1')"/>s
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Hosts/sec</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="format-number(/nmaprun/runstats/hosts/@total div /nmaprun/runstats/finished/@elapsed, '0.1')"/>
                    </span>
                  </div>
                </div>
              </div>

              <!-- Data Collection Summary -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Data Collected</h3>
                <div class="space-y-2">
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">OS Fingerprints</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="count(/nmaprun/host[os/osmatch])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Service Versions</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open' and service/@version])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">MAC Addresses</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="count(/nmaprun/host/address[@addrtype='mac'])"/>
                    </span>
                  </div>
                  <div class="flex justify-between items-center">
                    <span class="text-sm text-olive-700">Vulnerability Scans</span>
                    <span class="text-sm font-medium text-olive-900">
                      <xsl:value-of select="count(/nmaprun/host[script[@id='vulners']])"/>
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <!-- Top Services & OS Summary -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              <!-- Top Services -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">Top Services</h3>
                <div class="space-y-2">
                  <xsl:for-each select="/nmaprun/host/ports/port[state/@state='open']/service/@name[not(. = preceding::service/@name)]">
                    <xsl:sort select="count(/nmaprun/host/ports/port[state/@state='open']/service[@name=current()])" data-type="number" order="descending"/>
                    <xsl:if test="position() &lt;= 5">
                      <div class="flex justify-between items-center">
                        <span class="text-sm text-olive-700"><xsl:value-of select="."/></span>
                        <span class="text-sm font-medium text-olive-900">
                          <xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open']/service[@name=current()])"/>
                        </span>
                      </div>
                    </xsl:if>
                  </xsl:for-each>
                </div>
              </div>

              <!-- OS Distribution -->
              <div class="card p-4">
                <h3 class="text-lg font-semibold text-olive-900 mb-3">OS Distribution</h3>
                <div class="space-y-2">
                  <xsl:for-each select="/nmaprun/host/os/osmatch/@name[not(. = preceding::osmatch/@name)]">
                    <xsl:sort select="count(/nmaprun/host[os/osmatch/@name=current()])" data-type="number" order="descending"/>
                    <xsl:if test="position() &lt;= 5">
                      <div class="flex justify-between items-center">
                        <span class="text-sm text-olive-700 truncate max-w-xs" title="{.}">
                          <xsl:value-of select="substring(., 1, 30)"/>
                          <xsl:if test="string-length(.) > 30">...</xsl:if>
                        </span>
                        <span class="text-sm font-medium text-olive-900 ml-2">
                          <xsl:value-of select="count(/nmaprun/host[os/osmatch/@name=current()])"/>
                        </span>
                      </div>
                    </xsl:if>
                  </xsl:for-each>
                </div>
              </div>
            </div>
            
            <div class="progress-bar mb-6">
              <div class="progress-segment progress-success">
                <xsl:attribute name="style">width:<xsl:value-of select="/nmaprun/runstats/hosts/@up div /nmaprun/runstats/hosts/@total * 100"/>%;</xsl:attribute>
                <xsl:value-of select="/nmaprun/runstats/hosts/@up"/> Up
              </div>
              <div class="progress-segment progress-danger">
                <xsl:attribute name="style">width:<xsl:value-of select="/nmaprun/runstats/hosts/@down div /nmaprun/runstats/hosts/@total * 100"/>%;</xsl:attribute>
                <xsl:value-of select="/nmaprun/runstats/hosts/@down"/> Down
              </div>
            </div>
            
            <!-- Keyword Highlighting -->
            <div class="border-t border-olive-200 pt-6">
              <label class="block text-sm font-medium text-olive-900 mb-2">Highlight Keywords in Services</label>
              <textarea id="keyword-input" rows="2" placeholder="sha1, password, md5, login..." 
                        class="w-full mb-3">sha1,login,password,md5</textarea>
              <div class="flex space-x-3">
                <button id="highlight-button" onclick="highlight()">Apply Highlighting</button>
                <button onclick="document.location.reload(true);" class="bg-olive-400">Reset</button>
              </div>
            </div>
          </div>

          <!-- Scanned Hosts -->
          <div id="scannedhosts" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">
              Scanned Hosts
              <xsl:if test="/nmaprun/runstats/hosts/@down > 1024">
                <span class="text-lg text-olive-600 font-normal"> (offline hosts hidden)</span>
              </xsl:if>
            </h2>
            <div class="card p-6">
              <table id="table-overview" class="w-full">
                <thead>
                  <tr>
                    <th class="text-left">State</th>
                    <th class="text-left">Address</th>
                    <th class="text-left">Hostname</th>
                    <th class="text-left">TCP (open)</th>
                    <th class="text-left">UDP (open)</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:choose>
                    <xsl:when test="/nmaprun/runstats/hosts/@down > 1024">
                      <xsl:for-each select="/nmaprun/host[status/@state='up']">
                        <tr>
                          <td>
                            <span class="badge">
                              <xsl:attribute name="class">badge <xsl:choose><xsl:when test="status/@state='up'">badge-success</xsl:when><xsl:otherwise>badge-danger</xsl:otherwise></xsl:choose></xsl:attribute>
                              <xsl:value-of select="status/@state"/>
                            </span>
                          </td>
                          <td>
                            <a class="font-mono text-sm">
                              <xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                              <xsl:value-of select="address/@addr"/>
                            </a>
                          </td>
                          <td class="text-olive-700"><xsl:value-of select="hostnames/hostname/@name"/></td>
                          <td class="text-center"><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/></td>
                          <td class="text-center"><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/></td>
                        </tr>
                      </xsl:for-each>
                    </xsl:when>
                    <xsl:otherwise>
                      <xsl:for-each select="/nmaprun/host">
                        <tr>
                          <td>
                            <span class="badge">
                              <xsl:attribute name="class">badge <xsl:choose><xsl:when test="status/@state='up'">badge-success</xsl:when><xsl:otherwise>badge-danger</xsl:otherwise></xsl:choose></xsl:attribute>
                              <xsl:value-of select="status/@state"/>
                            </span>
                          </td>
                          <td>
                            <a class="font-mono text-sm">
                              <xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                              <xsl:value-of select="address/@addr"/>
                            </a>
                          </td>
                          <td class="text-olive-700"><xsl:value-of select="hostnames/hostname/@name"/></td>
                          <td class="text-center"><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/></td>
                          <td class="text-center"><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/></td>
                        </tr>
                      </xsl:for-each>
                    </xsl:otherwise>
                  </xsl:choose>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Open Services -->
          <div id="openservices" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Open Services</h2>
            <div class="card p-6">
              <table id="table-services" class="w-full text-sm">
                <thead>
                  <tr>
                    <th class="text-left">Hostname</th>
                    <th class="text-left">Address</th>
                    <th class="text-left">Port</th>
                    <th class="text-left">Protocol</th>
                    <th class="text-left">Service</th>
                    <th class="text-left">Product</th>
                    <th class="text-left">Version</th>
                    <th class="text-left">Extra</th>
                    <th class="text-left">SSL Cert</th>
                    <th class="text-left">Title</th>
                    <th class="text-left">CPE</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="/nmaprun/host">
                    <xsl:for-each select="ports/port[state/@state='open']">
                      <tr>
                        <td class="text-olive-700">
                          <xsl:choose>
                            <xsl:when test="count(../../hostnames/hostname) = 0">N/A</xsl:when>
                            <xsl:otherwise><xsl:value-of select="../../hostnames/hostname/@name"/></xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/></xsl:attribute>
                            <xsl:value-of select="../../address/@addr"/>
                          </a>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#port-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/>-<xsl:value-of select="@portid"/></xsl:attribute>
                            <xsl:value-of select="@portid"/>
                          </a>
                        </td>
                        <td><xsl:value-of select="@protocol"/></td>
                        <td>
                          <xsl:if test="count(service/@tunnel) > 0">
                            <span class="text-olive-600"><xsl:value-of select="service/@tunnel"/>/</span>
                          </xsl:if>
                          <xsl:value-of select="service/@name"/>
                        </td>
                        <td><xsl:value-of select="service/@product"/></td>
                        <td><xsl:value-of select="service/@version"/></td>
                        <td class="text-olive-600"><xsl:value-of select="service/@extrainfo"/></td>
                        <td class="text-xs">
                          <xsl:if test="count(script/table[@key='subject']/elem[@key='commonName']) > 0">
                            <div><span class="text-olive-600">CN:</span> <xsl:value-of select="script/table[@key='subject']/elem[@key='commonName']"/></div>
                          </xsl:if>
                          <xsl:if test="count(script/table[@key='validity']/elem[@key='notAfter']) > 0">
                            <div><span class="text-olive-600">Expiry:</span> <xsl:value-of select="script/table[@key='validity']/elem[@key='notAfter']"/></div>
                          </xsl:if>
                        </td>
                        <td class="italic text-olive-600">
                          <xsl:choose>
                            <xsl:when test="count(script[@id='http-title']/elem[@key='title']) > 0">
                              <xsl:value-of select="script[@id='http-title']/elem[@key='title']"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:if test="count(script[@id='http-title']/@output) > 0">
                                <xsl:value-of select="script[@id='http-title']/@output"/>
                              </xsl:if>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td class="font-mono text-xs">
                          <xsl:variable name="c22" select="service/cpe"/>
                          <xsl:variable name="afterA" select="substring-after($c22, 'cpe:/a:')"/>
                          <xsl:variable name="vendor" select="substring-before($afterA, ':')"/>
                          <xsl:variable name="afterVendor" select="substring-after($afterA, ':')"/>
                          <xsl:variable name="product" select="substring-before($afterVendor, ':')"/>
                          <xsl:variable name="verRaw" select="substring-after($afterVendor, ':')"/>
                          <xsl:variable name="verNorm" select="substring-before(concat($verRaw,'-'), '-')"/>
                          <xsl:variable name="verFinal" select="normalize-space($verNorm)"/>

                          <xsl:choose>
                            <xsl:when test="string($c22)">
                              <xsl:choose>
                                <xsl:when test="string-length($verFinal) &gt; 0">
                                  <a target="_blank" class="text-olive-700">
                                    <xsl:attribute name="href">https://cve.pentestfactory.de/?cpe=<xsl:value-of select="$c22"/></xsl:attribute>
                                    <xsl:value-of select="$c22"/>
                                  </a>
                                </xsl:when>
                                <xsl:otherwise><xsl:value-of select="$c22"/></xsl:otherwise>
                              </xsl:choose>
                            </xsl:when>
                            <xsl:otherwise><span class="text-olive-400">unknown</span></xsl:otherwise>
                          </xsl:choose>
                        </td>
                      </tr>
                    </xsl:for-each>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Web Services -->
          <div id="webservices" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Web Services</h2>
            <div class="card p-6">
              <table id="web-services" class="w-full text-sm">
                <thead>
                  <tr>
                    <th class="text-left">Hostname</th>
                    <th class="text-left">Address</th>
                    <th class="text-left">Port</th>
                    <th class="text-left">Service</th>
                    <th class="text-left">Product</th>
                    <th class="text-left">Version</th>
                    <th class="text-left">Title</th>
                    <th class="text-left">SSL Cert</th>
                    <th class="text-left">URL</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="/nmaprun/host">
                    <xsl:for-each select="ports/port[starts-with(service/@name, 'http') and state/@state='open' and @protocol='tcp']">
                      <tr>
                        <td class="text-olive-700">
                          <xsl:choose>
                            <xsl:when test="count(../../hostnames/hostname) = 0">N/A</xsl:when>
                            <xsl:otherwise><xsl:value-of select="../../hostnames/hostname/@name"/></xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/></xsl:attribute>
                            <xsl:value-of select="../../address/@addr"/>
                          </a>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#port-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/>-<xsl:value-of select="@portid"/></xsl:attribute>
                            <xsl:value-of select="@portid"/>
                          </a>
                        </td>
                        <td>
                          <xsl:if test="count(service/@tunnel) > 0">
                            <span class="text-olive-600"><xsl:value-of select="service/@tunnel"/>/</span>
                          </xsl:if>
                          <xsl:value-of select="service/@name"/>
                        </td>
                        <td><xsl:value-of select="service/@product"/></td>
                        <td><xsl:value-of select="service/@version"/></td>
                        <td class="italic text-olive-600">
                          <xsl:choose>
                            <xsl:when test="count(script[@id='http-title']/elem[@key='title']) > 0">
                              <xsl:value-of select="script[@id='http-title']/elem[@key='title']"/>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:if test="count(script[@id='http-title']/@output) > 0">
                                <xsl:value-of select="script[@id='http-title']/@output"/>
                              </xsl:if>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td class="text-xs">
                          <xsl:if test="count(script/table[@key='subject']/elem[@key='commonName']) > 0">
                            <div><span class="text-olive-600">CN:</span> <xsl:value-of select="script/table[@key='subject']/elem[@key='commonName']"/></div>
                          </xsl:if>
                          <xsl:if test="count(script/table[@key='validity']/elem[@key='notAfter']) > 0">
                            <div><span class="text-olive-600">Expiry:</span> <xsl:value-of select="script/table[@key='validity']/elem[@key='notAfter']"/></div>
                          </xsl:if>
                        </td>
                        <td>
                          <xsl:choose>
                            <xsl:when test="count(service/@tunnel) > 0 or service/@name = 'https' or service/@name = 'https-alt'">
                              <xsl:choose>
                                <xsl:when test="count(../../hostnames/hostname) > 0">
                                  <a target="_blank" class="font-mono text-xs">
                                    <xsl:attribute name="href">https://<xsl:value-of select="../../hostnames/hostname/@name"/>:<xsl:value-of select="@portid"/></xsl:attribute>
                                    https://<xsl:value-of select="../../hostnames/hostname/@name"/>:<xsl:value-of select="@portid"/>
                                  </a>
                                </xsl:when>
                                <xsl:otherwise>
                                  <a target="_blank" class="font-mono text-xs">
                                    <xsl:attribute name="href">https://<xsl:value-of select="../../address/@addr"/>:<xsl:value-of select="@portid"/></xsl:attribute>
                                    https://<xsl:value-of select="../../address/@addr"/>:<xsl:value-of select="@portid"/>
                                  </a>
                                </xsl:otherwise>
                              </xsl:choose>
                            </xsl:when>
                            <xsl:otherwise>
                              <xsl:choose>
                                <xsl:when test="count(../../hostnames/hostname) > 0">
                                  <a target="_blank" class="font-mono text-xs">
                                    <xsl:attribute name="href">http://<xsl:value-of select="../../hostnames/hostname/@name"/>:<xsl:value-of select="@portid"/></xsl:attribute>
                                    http://<xsl:value-of select="../../hostnames/hostname/@name"/>:<xsl:value-of select="@portid"/>
                                  </a>
                                </xsl:when>
                                <xsl:otherwise>
                                  <a target="_blank" class="font-mono text-xs">
                                    <xsl:attribute name="href">http://<xsl:value-of select="../../address/@addr"/>:<xsl:value-of select="@portid"/></xsl:attribute>
                                    http://<xsl:value-of select="../../address/@addr"/>:<xsl:value-of select="@portid"/>
                                  </a>
                                </xsl:otherwise>
                              </xsl:choose>
                            </xsl:otherwise>
                          </xsl:choose>
                        </td>
                      </tr>
                    </xsl:for-each>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Product Versions -->
          <div id="productversions" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Product Versions</h2>
            <div class="card p-6">
              <table id="table-product-versions" class="w-full text-sm">
                <thead>
                  <tr>
                    <th class="text-left">Product</th>
                    <th class="text-left">Version</th>
                    <th class="text-left">Count</th>
                    <th class="text-left">Host List</th>
                    <th class="text-left">CPE</th>
                  </tr>
                </thead>
                <tbody>
                  <xsl:for-each select="/nmaprun/host/ports/port[state/@state='open']/service[@product and @version][generate-id() = generate-id(key('svcByProdVer', concat(@product,'|',@version))[1])]">
                    <xsl:sort select="@product"/>
                    <xsl:sort select="@version"/>

                    <xsl:variable name="pv" select="concat(@product,'|',@version)"/>
                    <xsl:variable name="services" select="key('svcByProdVer', $pv)"/>
                    <xsl:variable name="uniqHosts" select="$services[generate-id() = generate-id(key('svcByProdVerHost', concat(@product,'|',@version,'|', ancestor::host/address/@addr))[1])]"/>
                    <xsl:variable name="cpe22" select="$services/cpe[starts-with(., 'cpe:/a:')][1]"/>
                    <xsl:variable name="afterA" select="substring-after($cpe22, 'cpe:/a:')"/>
                    <xsl:variable name="verRaw" select="substring-after(substring-after($afterA, ':'), ':')"/>
                    <xsl:variable name="verNorm" select="substring-before(concat($verRaw,'-'), '-')"/>
                    <xsl:variable name="verFinal" select="normalize-space($verNorm)"/>

                    <tr>
                      <td class="font-medium"><xsl:value-of select="@product"/></td>
                      <td><xsl:value-of select="@version"/></td>
                      <td class="text-center font-medium text-olive-700"><xsl:value-of select="count($uniqHosts)"/></td>
                      <td class="text-xs">
                        <xsl:for-each select="key('svcByProdVer', $pv)[generate-id() = generate-id(key('svcByProdVerHostPort', concat(@product,'|',@version,'|', ancestor::host/address/@addr,'|', ../@protocol,'|',../@portid))[1])]">
                          <xsl:sort select="ancestor::host/hostnames/hostname[1]/@name"/>
                          <xsl:sort select="ancestor::host/address/@addr"/>
                          <xsl:sort select="../@protocol"/>
                          <xsl:sort select="../@portid" data-type="number"/>

                          <xsl:variable name="h" select="ancestor::host"/>
                          <xsl:variable name="ip" select="$h/address/@addr"/>
                          <xsl:variable name="hn" select="$h/hostnames/hostname[1]/@name"/>
                          <xsl:variable name="proto" select="translate(../@protocol, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
                          <xsl:variable name="port" select="../@portid"/>

                          <a class="inline-block mb-1">
                            <xsl:attribute name="href">#port-<xsl:value-of select="translate($ip, '.', '-')"/>-<xsl:value-of select="$port"/></xsl:attribute>
                            <xsl:choose>
                              <xsl:when test="string-length($hn) &gt; 0">
                                <xsl:value-of select="$hn"/> (<xsl:value-of select="$ip"/>)
                              </xsl:when>
                              <xsl:otherwise><xsl:value-of select="$ip"/></xsl:otherwise>
                            </xsl:choose>
                            <span class="text-olive-600"> [<xsl:value-of select="$proto"/>/<xsl:value-of select="$port"/>]</span>
                          </a>
                          <xsl:if test="position() != last()">, </xsl:if>
                        </xsl:for-each>
                      </td>
                      <td class="font-mono text-xs">
                        <xsl:choose>
                          <xsl:when test="string($cpe22)">
                            <xsl:choose>
                              <xsl:when test="string-length($verFinal) &gt; 0">
                                <a target="_blank" class="text-olive-700">
                                  <xsl:attribute name="href">https://cve.pentestfactory.de/?cpe=<xsl:value-of select="$cpe22"/></xsl:attribute>
                                  <xsl:value-of select="$cpe22"/>
                                </a>
                              </xsl:when>
                              <xsl:otherwise><xsl:value-of select="$cpe22"/></xsl:otherwise>
                            </xsl:choose>
                          </xsl:when>
                          <xsl:otherwise><span class="text-olive-400">unknown</span></xsl:otherwise>
                        </xsl:choose>
                      </td>
                    </tr>
                  </xsl:for-each>
                </tbody>
              </table>
            </div>
          </div>

          <!-- SSH Authentication -->
          <xsl:if test="count(/nmaprun/host/ports/port[state/@state='open']/service[@name='ssh']) &gt; 0">
            <div id="ssh-auth" class="mb-12 fade-in">
              <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">SSH Authentication</h2>
              <div class="card p-6">
                <table id="table-ssh-auth" class="w-full text-sm">
                  <thead>
                    <tr>
                      <th class="text-left">Host</th>
                      <th class="text-left">IP</th>
                      <th class="text-left">Port</th>
                      <th class="text-left">Product</th>
                      <th class="text-left">Version</th>
                      <th class="text-left">Auth Methods</th>
                    </tr>
                  </thead>
                  <tbody>
                    <xsl:for-each select="key('sshSvcs', 1)">
                      <xsl:sort select="ancestor::host/hostnames/hostname[1]/@name"/>
                      <xsl:sort select="ancestor::host/address/@addr"/>
                      <xsl:sort select="../@portid" data-type="number"/>

                      <xsl:variable name="host" select="ancestor::host"/>
                      <xsl:variable name="ip" select="$host/address/@addr"/>
                      <xsl:variable name="hn" select="$host/hostnames/hostname[1]/@name"/>
                      <xsl:variable name="port" select="../@portid"/>
                      <xsl:variable name="proto" select="translate(../@protocol,'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ')"/>
                      <xsl:variable name="methods" select="../script[@id='ssh-auth-methods']/table[@key='Supported authentication methods']/elem"/>

                      <tr>
                        <td class="text-olive-700">
                          <xsl:choose>
                            <xsl:when test="string-length($hn) &gt; 0"><xsl:value-of select="$hn"/></xsl:when>
                            <xsl:otherwise>-</xsl:otherwise>
                          </xsl:choose>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#onlinehosts-<xsl:value-of select="translate($ip,'.','-')"/></xsl:attribute>
                            <xsl:value-of select="$ip"/>
                          </a>
                        </td>
                        <td>
                          <a class="font-mono">
                            <xsl:attribute name="href">#port-<xsl:value-of select="translate($ip,'.','-')"/>-<xsl:value-of select="$port"/></xsl:attribute>
                            <xsl:value-of select="$proto"/>/<xsl:value-of select="$port"/>
                          </a>
                        </td>
                        <td><xsl:value-of select="@product"/></td>
                        <td><xsl:value-of select="@version"/></td>
                        <td>
                          <xsl:choose>
                            <xsl:when test="count($methods) &gt; 0">
                              <xsl:for-each select="$methods">
                                <span class="badge badge-warning mr-1"><xsl:value-of select="."/></span>
                              </xsl:for-each>
                            </xsl:when>
                            <xsl:otherwise>-</xsl:otherwise>
                          </xsl:choose>
                        </td>
                      </tr>
                    </xsl:for-each>
                  </tbody>
                </table>
              </div>
            </div>
          </xsl:if>

          <!-- Online Hosts -->
          <div id="onlinehosts" class="mb-12 fade-in">
            <h2 class="text-3xl font-display font-bold text-olive-900 mb-6">Online Hosts</h2>
            
            <xsl:for-each select="/nmaprun/host[status/@state='up']">
              <div class="card mb-6">
                <div class="collapsible-header p-6 border-b border-olive-200">
                  <xsl:attribute name="id">onlinehosts-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                  <xsl:attribute name="onclick">toggleCollapse('<xsl:value-of select="translate(address/@addr, '.', '-')"/>')</xsl:attribute>
                  <div class="flex items-center justify-between">
                    <div>
                      <h3 class="text-xl font-display font-bold text-olive-900">
                        <span class="chevron inline-block mr-2">▼</span>
                        <xsl:value-of select="address/@addr"/>
                        <xsl:if test="count(hostnames/hostname) > 0">
                          <span class="text-olive-600 font-normal"> – <xsl:value-of select="hostnames/hostname/@name"/></span>
                        </xsl:if>
                      </h3>
                    </div>
                    <span class="badge badge-success">
                      <xsl:value-of select="count(ports/port[state/@state='open'])"/> open ports
                    </span>
                  </div>
                </div>
                
                <div class="p-6">
                  <xsl:attribute name="id">content-<xsl:value-of select="translate(address/@addr, '.', '-')"/></xsl:attribute>
                  
                  <xsl:if test="count(hostnames/hostname) > 0">
                    <div class="mb-6">
                      <h4 class="text-lg font-display font-semibold text-olive-900 mb-3">Hostnames</h4>
                      <ul class="list-disc list-inside space-y-1">
                        <xsl:for-each select="hostnames/hostname">
                          <li class="text-olive-700">
                            <xsl:value-of select="@name"/> 
                            <span class="text-olive-500">(<xsl:value-of select="@type"/>)</span>
                          </li>
                        </xsl:for-each>
                      </ul>
                    </div>
                  </xsl:if>
                  
                  <div class="mb-6">
                    <h4 class="text-lg font-display font-semibold text-olive-900 mb-3">Ports</h4>
                    <div class="overflow-x-auto">
                      <table class="w-full text-sm">
                        <thead>
                          <tr>
                            <th class="text-left">Port</th>
                            <th class="text-left">Protocol</th>
                            <th class="text-left">State/Reason</th>
                            <th class="text-left">Service</th>
                            <th class="text-left">Product</th>
                            <th class="text-left">Version</th>
                            <th class="text-left">Extra Info</th>
                          </tr>
                        </thead>
                        <tbody>
                          <xsl:for-each select="ports/port">
                            <tr>
                              <xsl:attribute name="class">
                                <xsl:choose>
                                  <xsl:when test="state/@state = 'open'">bg-olive-50</xsl:when>
                                  <xsl:when test="state/@state = 'filtered'">bg-yellow-50</xsl:when>
                                  <xsl:otherwise>bg-gray-50</xsl:otherwise>
                                </xsl:choose>
                              </xsl:attribute>
                              <td class="font-mono">
                                <xsl:attribute name="id">port-<xsl:value-of select="translate(../../address/@addr, '.', '-')"/>-<xsl:value-of select="@portid"/></xsl:attribute>
                                <xsl:value-of select="@portid"/>
                              </td>
                              <td><xsl:value-of select="@protocol"/></td>
                              <td>
                                <div><xsl:value-of select="state/@state"/></div>
                                <div class="text-xs text-olive-600"><xsl:value-of select="state/@reason"/></div>
                              </td>
                              <td>
                                <xsl:if test="count(service/@tunnel) > 0">
                                  <span class="text-olive-600"><xsl:value-of select="service/@tunnel"/>/</span>
                                </xsl:if>
                                <xsl:value-of select="service/@name"/>
                              </td>
                              <td><xsl:value-of select="service/@product"/></td>
                              <td><xsl:value-of select="service/@version"/></td>
                              <td class="text-olive-600"><xsl:value-of select="service/@extrainfo"/></td>
                            </tr>
                            <xsl:if test="count(service/cpe) > 0 or count(script) > 0">
                              <tr>
                                <xsl:attribute name="class">
                                  <xsl:choose>
                                    <xsl:when test="state/@state = 'open'">bg-olive-50</xsl:when>
                                    <xsl:when test="state/@state = 'filtered'">bg-yellow-50</xsl:when>
                                    <xsl:otherwise>bg-gray-50</xsl:otherwise>
                                  </xsl:choose>
                                </xsl:attribute>
                                <td colspan="7" class="text-xs">
                                  <xsl:if test="count(service/cpe) > 0">
                                    <div class="mb-2">
                                      <a target="_blank" class="font-mono text-olive-700">
                                        <xsl:attribute name="href">https://nvd.nist.gov/vuln/search/results?form_type=Advanced&amp;cves=on&amp;cpe_version=<xsl:value-of select="service/cpe"/></xsl:attribute>
                                        <xsl:value-of select="service/cpe"/>
                                      </a>
                                    </div>
                                  </xsl:if>
                                  <xsl:for-each select="script">
                                    <div class="mb-3">
                                      <h5 class="font-semibold text-olive-800 mb-1"><xsl:value-of select="@id"/></h5>
                                      <pre class="text-xs bg-white p-3 rounded border border-olive-200 overflow-x-auto"><xsl:value-of select="@output"/></pre>
                                    </div>
                                  </xsl:for-each>
                                </td>
                              </tr>
                            </xsl:if>
                          </xsl:for-each>
                        </tbody>
                      </table>
                    </div>
                  </div>
                  
                  <xsl:if test="count(hostscript/script) > 0">
                    <div class="mb-6">
                      <h4 class="text-lg font-display font-semibold text-olive-900 mb-3">Host Scripts</h4>
                      <xsl:for-each select="hostscript/script">
                        <div class="mb-3">
                          <h5 class="font-semibold text-olive-800 mb-1"><xsl:value-of select="@id"/></h5>
                          <pre class="text-xs bg-white p-3 rounded border border-olive-200 overflow-x-auto"><xsl:value-of select="@output"/></pre>
                        </div>
                      </xsl:for-each>
                    </div>
                  </xsl:if>
                  
                  <xsl:if test="count(os/osmatch) > 0">
                    <div>
                      <h4 class="text-lg font-display font-semibold text-olive-900 mb-3">OS Detection</h4>
                      <xsl:for-each select="os/osmatch">
                        <div class="mb-4 p-4 bg-olive-50 rounded-lg border border-olive-200">
                          <h5 class="font-semibold text-olive-900 mb-2">
                            <xsl:value-of select="@name"/> 
                            <span class="text-olive-600">(<xsl:value-of select="@accuracy"/>% accuracy)</span>
                          </h5>
                          <xsl:for-each select="osclass">
                            <div class="text-sm text-olive-700 space-y-1">
                              <div><span class="font-medium">Device type:</span> <xsl:value-of select="@type"/></div>
                              <div><span class="font-medium">Running:</span> <xsl:value-of select="@vendor"/> <xsl:value-of select="@osfamily"/> <xsl:value-of select="@osgen"/> (<xsl:value-of select="@accuracy"/>%)</div>
                              <div>
                                <span class="font-medium">OS CPE:</span> 
                                <a target="_blank" class="font-mono text-xs text-olive-700">
                                  <xsl:attribute name="href">https://nvd.nist.gov/vuln/search/results?form_type=Advanced&amp;cves=on&amp;cpe_version=<xsl:value-of select="cpe"/></xsl:attribute>
                                  <xsl:value-of select="cpe"/>
                                </a>
                              </div>
                            </div>
                          </xsl:for-each>
                        </div>
                      </xsl:for-each>
                    </div>
                  </xsl:if>
                </div>
              </div>
            </xsl:for-each>
          </div>
        </div>

        <!-- Footer -->
        <footer class="bg-white border-t border-olive-200 py-12 mt-12">
          <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center text-sm text-olive-600">
            <p class="mb-2">
              Report generated by <a href="https://pentestfactory.com" class="text-olive-700 hover:text-olive-900">Pentest Factory GmbH</a>
            </p>
            <p class="mb-4">
              Questions or problems? <a href="mailto:team@pentestfactory.de" class="text-olive-700 hover:text-olive-900">Contact us</a>
            </p>
            <p class="text-xs">
              ❤️ Original Bootstrap template by <a href="https://github.com/honze-net/nmap-bootstrap-xsl" target="_blank" class="text-olive-700">Andreas Hontzia</a> ·
              Tweaks by <a href="https://github.com/l4rm4nd" target="_blank" class="text-olive-700">LRVT</a> ·
              Modern design update 2026 ·
              Techmore Network Scanner <xsl:value-of select="$techmore_version"/>
            </p>
          </div>
        </footer>

        <!-- Scripts -->
        <script>
          function highlight() {
            $("#table-services").dataTable().fnDestroy();
            let keywords = document.getElementById('keyword-input').value.split(',');
            let content = document.getElementById('table-services').innerHTML;
            document.getElementById('table-services').innerHTML = transformContent(content, keywords);
            initServicesTable();
          }

          function transformContent(content, keywords) {
            let temp = content;
            keywords.forEach(keyword => {
              temp = temp.replace(new RegExp(keyword.trim(), 'ig'), 
                (match) => `<span class="highlight-keyword">${match}</span>`);
            });
            return temp;
          }

          function toggleCollapse(id) {
            const content = document.getElementById('content-' + id);
            const header = document.getElementById('onlinehosts-' + id);
            const chevron = header.querySelector('.chevron');
            
            if (content.style.display === 'none') {
              content.style.display = 'block';
              chevron.classList.remove('collapsed');
            } else {
              content.style.display = 'none';
              chevron.classList.add('collapsed');
            }
          }

          function initServicesTable() {
            $('#table-services').DataTable({
              lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]],
              order: [[0, 'asc']],
              columnDefs: [
                { targets: [1], type: 'ip-address' }
              ],
              dom: 'lBfrtip',
              stateSave: true,
              buttons: ['copy', 'csv', 'excel', 'pdf']
            });
          }

          $(document).ready(function() {
            // Initialize all tables
            $('#table-overview').DataTable({
              lengthMenu: [[10, 25, 50, -1], [10, 25, 50, "All"]],
              columnDefs: [{ targets: [1], type: 'ip-address' }]
            });

            initServicesTable();

            $('#web-services').DataTable({
              lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]],
              order: [[0, 'asc']],
              columnDefs: [{ targets: [1], type: 'ip-address' }],
              dom: 'lBfrtip',
              stateSave: true,
              buttons: ['copy', 'csv', 'excel', 'pdf']
            });

            $('#table-product-versions').DataTable({
              lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]],
              order: [[0, 'asc'], [1, 'asc']],
              dom: 'lBfrtip',
              stateSave: true,
              buttons: ['copy', 'csv', 'excel', 'pdf']
            });

            if ($('#table-ssh-auth').length) {
              $('#table-ssh-auth').DataTable({
                lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, "All"]],
                order: [[0, 'asc'], [2, 'asc']],
                columnDefs: [{ targets: 1, type: 'ip-address' }],
                dom: 'lBfrtip',
                stateSave: true,
                buttons: ['copy', 'csv', 'excel', 'pdf']
              });
            }

            // Smooth scrolling for anchor links
            $("a[href^='#']").click(function(e) {
              e.preventDefault();
              const target = $(this.hash);
              if (target.length) {
                $('html, body').animate({
                  scrollTop: target.offset().top - 80
                }, 500);
              }
            });
          });
        </script>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
