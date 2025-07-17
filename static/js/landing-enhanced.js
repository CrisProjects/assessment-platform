/**
 * Script de mejoras para la Landing Page
 * Inspirado en el diseño de Calm.com
 */

document.addEventListener('DOMContentLoaded', function() {
    
    // ==========================================
    // INICIALIZACIÓN Y CONFIGURACIÓN
    // ==========================================
    
    const CONFIG = {
        ANIMATION_DURATION: 800,
        SCROLL_THRESHOLD: 0.1,
        PARALLAX_SPEED: 0.3,
        INTERSECTION_MARGIN: '-50px'
    };

    // ==========================================
    // ANIMACIONES DE SCROLL AVANZADAS
    // ==========================================
    
    class ScrollAnimationManager {
        constructor() {
            this.elements = new Map();
            this.isIntersecting = false;
            this.setupIntersectionObserver();
        }

        setupIntersectionObserver() {
            const observerOptions = {
                threshold: CONFIG.SCROLL_THRESHOLD,
                rootMargin: `0px 0px ${CONFIG.INTERSECTION_MARGIN} 0px`
            };

            this.observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    const element = entry.target;
                    const animationData = this.elements.get(element);
                    
                    if (entry.isIntersecting && animationData) {
                        this.animateElement(element, animationData);
                        this.observer.unobserve(element);
                    }
                });
            }, observerOptions);
        }

        registerElement(element, animationType = 'fadeInUp', delay = 0) {
            const animationData = {
                type: animationType,
                delay: delay,
                isAnimated: false
            };
            
            this.elements.set(element, animationData);
            this.prepareElement(element, animationType);
            this.observer.observe(element);
        }

        prepareElement(element, animationType) {
            element.style.transition = `opacity ${CONFIG.ANIMATION_DURATION}ms ease-out, transform ${CONFIG.ANIMATION_DURATION}ms ease-out`;
            
            switch(animationType) {
                case 'fadeInUp':
                    element.style.opacity = '0';
                    element.style.transform = 'translateY(30px)';
                    break;
                case 'fadeInLeft':
                    element.style.opacity = '0';
                    element.style.transform = 'translateX(-30px)';
                    break;
                case 'fadeInRight':
                    element.style.opacity = '0';
                    element.style.transform = 'translateX(30px)';
                    break;
                case 'scaleIn':
                    element.style.opacity = '0';
                    element.style.transform = 'scale(0.8)';
                    break;
            }
        }

        animateElement(element, animationData) {
            setTimeout(() => {
                element.style.opacity = '1';
                element.style.transform = 'translateY(0) translateX(0) scale(1)';
                animationData.isAnimated = true;
            }, animationData.delay);
        }
    }

    // ==========================================
    // EFECTOS PARALLAX Y SCROLL
    // ==========================================
    
    class ParallaxManager {
        constructor() {
            this.hero = document.querySelector('.hero');
            this.ticking = false;
            this.isReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            
            if (!this.isReducedMotion && this.hero) {
                this.setupParallax();
            }
        }

        setupParallax() {
            window.addEventListener('scroll', () => this.requestTick(), { passive: true });
        }

        requestTick() {
            if (!this.ticking) {
                requestAnimationFrame(() => this.updateParallax());
                this.ticking = true;
            }
        }

        updateParallax() {
            const scrolled = window.pageYOffset;
            const speed = scrolled * CONFIG.PARALLAX_SPEED;
            
            if (this.hero && scrolled < window.innerHeight) {
                this.hero.style.transform = `translateY(${speed}px)`;
            }
            
            this.ticking = false;
        }
    }

    // ==========================================
    // GESTOR DE NAVEGACIÓN SUAVE
    // ==========================================
    
    class SmoothNavigationManager {
        constructor() {
            this.setupSmoothScrolling();
            this.setupPreloading();
        }

        setupSmoothScrolling() {
            // Scroll suave para el indicador de scroll
            const scrollIndicator = document.querySelector('.scroll-indicator');
            if (scrollIndicator) {
                scrollIndicator.addEventListener('click', (e) => {
                    e.preventDefault();
                    const target = document.querySelector('.features');
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            }

            // Scroll suave para todos los enlaces internos
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', (e) => {
                    e.preventDefault();
                    const target = document.querySelector(anchor.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            });
        }

        setupPreloading() {
            const ctaButton = document.querySelector('.cta-button');
            if (ctaButton) {
                // Preload de la página de destino para mejor UX
                ctaButton.addEventListener('mouseenter', () => {
                    this.preloadPage('/dashboard-selection');
                }, { once: true });

                // Añadir feedback visual al hacer clic
                ctaButton.addEventListener('click', (e) => {
                    this.addClickFeedback(ctaButton);
                });
            }
        }

        preloadPage(url) {
            const link = document.createElement('link');
            link.rel = 'prefetch';
            link.href = url;
            document.head.appendChild(link);
        }

        addClickFeedback(button) {
            button.style.transform = 'scale(0.95)';
            setTimeout(() => {
                button.style.transform = '';
            }, 150);
        }
    }

    // ==========================================
    // GESTOR DE PERFORMANCE Y LAZY LOADING
    // ==========================================
    
    class PerformanceManager {
        constructor() {
            this.setupLazyLoading();
            this.optimizeAnimations();
        }

        setupLazyLoading() {
            // Lazy loading para imágenes si las hubiera
            const images = document.querySelectorAll('img[data-src]');
            if (images.length > 0) {
                const imageObserver = new IntersectionObserver((entries) => {
                    entries.forEach(entry => {
                        if (entry.isIntersecting) {
                            const img = entry.target;
                            img.src = img.dataset.src;
                            img.classList.remove('lazy');
                            imageObserver.unobserve(img);
                        }
                    });
                });

                images.forEach(img => imageObserver.observe(img));
            }
        }

        optimizeAnimations() {
            // Pausar animaciones cuando la pestaña no está visible
            document.addEventListener('visibilitychange', () => {
                const animatedElements = document.querySelectorAll('.hero::before, .cta-button');
                if (document.hidden) {
                    animatedElements.forEach(el => {
                        el.style.animationPlayState = 'paused';
                    });
                } else {
                    animatedElements.forEach(el => {
                        el.style.animationPlayState = 'running';
                    });
                }
            });
        }
    }

    // ==========================================
    // INICIALIZACIÓN PRINCIPAL
    // ==========================================
    
    function initializeApp() {
        // Crear instancias de los gestores
        const scrollManager = new ScrollAnimationManager();
        const parallaxManager = new ParallaxManager();
        const navigationManager = new SmoothNavigationManager();
        const performanceManager = new PerformanceManager();

        // Registrar elementos para animación
        const featureCards = document.querySelectorAll('.feature-card');
        const featuresHeader = document.querySelector('.features-header');
        
        if (featuresHeader) {
            scrollManager.registerElement(featuresHeader, 'fadeInUp', 0);
        }

        featureCards.forEach((card, index) => {
            scrollManager.registerElement(card, 'fadeInUp', index * 200);
        });

        // Manejar errores de carga
        window.addEventListener('error', (e) => {
            console.warn('Asset failed to load:', e.target.src || e.target.href);
        });

        // Log de inicialización exitosa
        console.log('✅ Landing Page initialized successfully');
    }

    // ==========================================
    // UTILIDADES ADICIONALES
    // ==========================================
    
    // Detectar capacidades del dispositivo
    function detectDeviceCapabilities() {
        const capabilities = {
            hasTouch: 'ontouchstart' in window,
            hasHover: window.matchMedia('(hover: hover)').matches,
            prefersReducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
            isHighDPI: window.devicePixelRatio > 1
        };

        // Añadir clases CSS basadas en capacidades
        const html = document.documentElement;
        Object.entries(capabilities).forEach(([key, value]) => {
            if (value) {
                html.classList.add(key.replace(/([A-Z])/g, '-$1').toLowerCase());
            }
        });

        return capabilities;
    }

    // Inicializar la aplicación
    detectDeviceCapabilities();
    initializeApp();

    // Añadir soporte para debugging en desarrollo
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        window.landingPageUtils = {
            scrollManager: ScrollAnimationManager,
            parallaxManager: ParallaxManager,
            config: CONFIG
        };
    }
});
