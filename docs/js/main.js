// Gecko landing page scripts

document.addEventListener('DOMContentLoaded', function() {
    // Intersection Observer for scroll animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, observerOptions);

    // Observe all sections for scroll animations
    document.querySelectorAll('section').forEach(section => {
        observer.observe(section);
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add copy functionality to code blocks
    document.querySelectorAll('.code-block').forEach(block => {
        block.addEventListener('click', function() {
            const code = this.innerText;
            navigator.clipboard.writeText(code).then(() => {
                // Add copied class for visual feedback
                this.classList.add('copied');
                setTimeout(() => {
                    this.classList.remove('copied');
                }, 2000);
            }).catch(() => {
                // Clipboard API not available, silently fail
            });
        });
        block.style.cursor = 'pointer';
    });

    // Parallax effect on scroll for header
    const logo = document.querySelector('.logo');
    let ticking = false;

    window.addEventListener('scroll', () => {
        if (!ticking) {
            requestAnimationFrame(() => {
                const scrolled = window.pageYOffset;
                if (logo && scrolled < 400) {
                    logo.style.transform = `translateY(${scrolled * 0.3}px)`;
                }
                ticking = false;
            });
            ticking = true;
        }
    });

    // Feature cards staggered animation
    const features = document.querySelectorAll('.feature');
    features.forEach((feature, index) => {
        feature.style.animationDelay = `${index * 0.1}s`;
    });

    // Add typing effect to code blocks on first view
    const codeBlocks = document.querySelectorAll('.code-block code');
    const codeObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting && !entry.target.dataset.animated) {
                entry.target.dataset.animated = 'true';
                entry.target.style.opacity = '0';
                setTimeout(() => {
                    entry.target.style.transition = 'opacity 0.5s ease';
                    entry.target.style.opacity = '1';
                }, 100);
            }
        });
    }, { threshold: 0.5 });

    codeBlocks.forEach(block => codeObserver.observe(block));

    // Mouse glow effect on feature cards
    document.querySelectorAll('.feature').forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            card.style.setProperty('--mouse-x', `${x}px`);
            card.style.setProperty('--mouse-y', `${y}px`);
        });
    });
});
