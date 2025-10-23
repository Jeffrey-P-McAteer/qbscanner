#include "bitmap_renderer.h"
#include <iostream>
#include <algorithm>
#include <cstring>
#include <fstream>

#ifdef HAS_STB_TRUETYPE
#define STB_TRUETYPE_IMPLEMENTATION
#include "stb_truetype.h"
#endif

#ifdef HAS_STB_IMAGE_WRITE
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"
#endif

BitmapRenderer::BitmapRenderer(int w, int h) : width(w), height(h) {
    pixels.resize(width * height * 4, 255); // Initialize to white
    loadSystemFont();
}

BitmapRenderer::~BitmapRenderer() {
#ifdef HAS_STB_TRUETYPE
    if (font_info) {
        delete static_cast<stbtt_fontinfo*>(font_info);
    }
#endif
}

bool BitmapRenderer::loadSystemFont() {
#ifdef HAS_STB_TRUETYPE
    // Try to load a system font
    std::vector<std::string> font_paths = {
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/arial.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/System/Library/Fonts/Arial.ttf",
        "/Windows/Fonts/arial.ttf"
    };
    
    for (const auto& font_path : font_paths) {
        std::ifstream font_file(font_path, std::ios::binary);
        if (font_file.is_open()) {
            font_file.seekg(0, std::ios::end);
            size_t font_size = font_file.tellg();
            font_file.seekg(0, std::ios::beg);
            
            font_data.resize(font_size);
            font_file.read(reinterpret_cast<char*>(font_data.data()), font_size);
            font_file.close();
            
            font_info = new stbtt_fontinfo;
            if (stbtt_InitFont(static_cast<stbtt_fontinfo*>(font_info), font_data.data(), 0)) {
                font_loaded = true;
                std::cout << "Loaded font: " << font_path << std::endl;
                return true;
            } else {
                delete static_cast<stbtt_fontinfo*>(font_info);
                font_info = nullptr;
            }
        }
    }
    
    std::cout << "Warning: No system font found, text rendering disabled" << std::endl;
#endif
    return false;
}

void BitmapRenderer::clear(Color color) {
    for (int i = 0; i < width * height; i++) {
        pixels[i * 4 + 0] = color.r;
        pixels[i * 4 + 1] = color.g;
        pixels[i * 4 + 2] = color.b;
        pixels[i * 4 + 3] = color.a;
    }
}

void BitmapRenderer::setPixel(int x, int y, Color color) {
    if (x >= 0 && x < width && y >= 0 && y < height) {
        int index = (y * width + x) * 4;
        pixels[index + 0] = color.r;
        pixels[index + 1] = color.g;
        pixels[index + 2] = color.b;
        pixels[index + 3] = color.a;
    }
}

Color BitmapRenderer::getPixel(int x, int y) const {
    if (x >= 0 && x < width && y >= 0 && y < height) {
        int index = (y * width + x) * 4;
        return Color(pixels[index + 0], pixels[index + 1], pixels[index + 2], pixels[index + 3]);
    }
    return Color::white();
}

void BitmapRenderer::blendPixel(int x, int y, Color color, float alpha) {
    if (x >= 0 && x < width && y >= 0 && y < height) {
        Color current = getPixel(x, y);
        float inv_alpha = 1.0f - alpha;
        Color blended(
            static_cast<unsigned char>(current.r * inv_alpha + color.r * alpha),
            static_cast<unsigned char>(current.g * inv_alpha + color.g * alpha),
            static_cast<unsigned char>(current.b * inv_alpha + color.b * alpha),
            255
        );
        setPixel(x, y, blended);
    }
}

void BitmapRenderer::drawLine(Point start, Point end, Color color, float thickness) {
    if (thickness <= 1.0f) {
        // Simple line drawing using Bresenham's algorithm
        int x0 = static_cast<int>(start.x);
        int y0 = static_cast<int>(start.y);
        int x1 = static_cast<int>(end.x);
        int y1 = static_cast<int>(end.y);
        
        int dx = abs(x1 - x0);
        int dy = abs(y1 - y0);
        int sx = (x0 < x1) ? 1 : -1;
        int sy = (y0 < y1) ? 1 : -1;
        int err = dx - dy;
        
        while (true) {
            setPixel(x0, y0, color);
            
            if (x0 == x1 && y0 == y1) break;
            
            int e2 = 2 * err;
            if (e2 > -dy) {
                err -= dy;
                x0 += sx;
            }
            if (e2 < dx) {
                err += dx;
                y0 += sy;
            }
        }
    } else {
        drawThickLine(start, end, thickness, color);
    }
}

void BitmapRenderer::drawThickLine(Point start, Point end, float thickness, Color color) {
    double dx = end.x - start.x;
    double dy = end.y - start.y;
    double length = sqrt(dx * dx + dy * dy);
    
    if (length == 0) return;
    
    // Normalize direction vector
    dx /= length;
    dy /= length;
    
    // Perpendicular vector
    double px = -dy * thickness / 2.0;
    double py = dx * thickness / 2.0;
    
    // Draw thick line as a filled polygon
    Point corners[4] = {
        Point(start.x + px, start.y + py),
        Point(start.x - px, start.y - py),
        Point(end.x - px, end.y - py),
        Point(end.x + px, end.y + py)
    };
    
    // Simple scanline fill for the thick line
    for (int y = std::max(0, static_cast<int>(std::min({corners[0].y, corners[1].y, corners[2].y, corners[3].y})));
         y <= std::min(height - 1, static_cast<int>(std::max({corners[0].y, corners[1].y, corners[2].y, corners[3].y}))); y++) {
        
        std::vector<int> intersections;
        for (int i = 0; i < 4; i++) {
            int j = (i + 1) % 4;
            if ((corners[i].y <= y && corners[j].y > y) || (corners[j].y <= y && corners[i].y > y)) {
                double x = corners[i].x + (y - corners[i].y) * (corners[j].x - corners[i].x) / (corners[j].y - corners[i].y);
                intersections.push_back(static_cast<int>(x));
            }
        }
        
        std::sort(intersections.begin(), intersections.end());
        for (size_t i = 0; i < intersections.size(); i += 2) {
            if (i + 1 < intersections.size()) {
                for (int x = std::max(0, intersections[i]); x <= std::min(width - 1, intersections[i + 1]); x++) {
                    setPixel(x, y, color);
                }
            }
        }
    }
}

void BitmapRenderer::drawCircle(Point center, double radius, Color fillColor, Color borderColor, float borderWidth) {
    int cx = static_cast<int>(center.x);
    int cy = static_cast<int>(center.y);
    int r = static_cast<int>(radius);
    
    // Fill circle
    for (int y = -r; y <= r; y++) {
        for (int x = -r; x <= r; x++) {
            if (x * x + y * y <= r * r) {
                setPixel(cx + x, cy + y, fillColor);
            }
        }
    }
    
    // Draw border
    if (borderWidth > 0) {
        int outer_r = r;
        int inner_r = static_cast<int>(r - borderWidth);
        
        for (int y = -outer_r; y <= outer_r; y++) {
            for (int x = -outer_r; x <= outer_r; x++) {
                int dist_sq = x * x + y * y;
                if (dist_sq <= outer_r * outer_r && dist_sq >= inner_r * inner_r) {
                    setPixel(cx + x, cy + y, borderColor);
                }
            }
        }
    }
}

void BitmapRenderer::drawRect(Rect rect, Color fillColor, Color borderColor, float borderWidth) {
    int x1 = static_cast<int>(rect.x);
    int y1 = static_cast<int>(rect.y);
    int x2 = static_cast<int>(rect.x + rect.width);
    int y2 = static_cast<int>(rect.y + rect.height);
    
    // Fill rectangle
    for (int y = y1; y < y2; y++) {
        for (int x = x1; x < x2; x++) {
            setPixel(x, y, fillColor);
        }
    }
    
    // Draw border
    if (borderWidth > 0) {
        int bw = static_cast<int>(borderWidth);
        
        // Top and bottom borders
        for (int i = 0; i < bw; i++) {
            for (int x = x1; x < x2; x++) {
                setPixel(x, y1 + i, borderColor);
                setPixel(x, y2 - 1 - i, borderColor);
            }
        }
        
        // Left and right borders
        for (int i = 0; i < bw; i++) {
            for (int y = y1; y < y2; y++) {
                setPixel(x1 + i, y, borderColor);
                setPixel(x2 - 1 - i, y, borderColor);
            }
        }
    }
}

void BitmapRenderer::drawText(const std::string& text, Point position, float fontSize, Color color, bool bold) {
#ifdef HAS_STB_TRUETYPE
    if (!font_loaded || !font_info) {
        // Fallback: draw simple rectangles for each character
        for (size_t i = 0; i < text.length(); i++) {
            int x = static_cast<int>(position.x + i * fontSize * 0.6);
            int y = static_cast<int>(position.y);
            drawRect(Rect(x, y, fontSize * 0.5, fontSize), color);
        }
        return;
    }
    
    stbtt_fontinfo* font = static_cast<stbtt_fontinfo*>(font_info);
    float scale = stbtt_ScaleForPixelHeight(font, fontSize);
    
    int ascent, descent, lineGap;
    stbtt_GetFontVMetrics(font, &ascent, &descent, &lineGap);
    
    float x = position.x;
    float baseline = position.y + ascent * scale;
    
    for (char c : text) {
        if (c < 32 || c > 126) continue; // Skip non-printable characters
        
        int advanceWidth, leftSideBearing;
        stbtt_GetCodepointHMetrics(font, c, &advanceWidth, &leftSideBearing);
        
        int x0, y0, x1, y1;
        stbtt_GetCodepointBitmapBox(font, c, scale, scale, &x0, &y0, &x1, &y1);
        
        int char_width = x1 - x0;
        int char_height = y1 - y0;
        
        if (char_width > 0 && char_height > 0) {
            std::vector<unsigned char> bitmap(char_width * char_height);
            stbtt_MakeCodepointBitmap(font, bitmap.data(), char_width, char_height, char_width, scale, scale, c);
            
            // Render the character bitmap
            for (int py = 0; py < char_height; py++) {
                for (int px = 0; px < char_width; px++) {
                    unsigned char alpha = bitmap[py * char_width + px];
                    if (alpha > 0) {
                        int screen_x = static_cast<int>(x + leftSideBearing * scale + x0 + px);
                        int screen_y = static_cast<int>(baseline + y0 + py);
                        
                        if (bold) {
                            // Simple bold effect by drawing slightly offset
                            blendPixel(screen_x, screen_y, color, alpha / 255.0f);
                            blendPixel(screen_x + 1, screen_y, color, alpha / 255.0f);
                        } else {
                            blendPixel(screen_x, screen_y, color, alpha / 255.0f);
                        }
                    }
                }
            }
        }
        
        x += advanceWidth * scale;
    }
#else
    // Fallback: draw simple rectangles for each character
    for (size_t i = 0; i < text.length(); i++) {
        int x = static_cast<int>(position.x + i * fontSize * 0.6);
        int y = static_cast<int>(position.y);
        drawRect(Rect(x, y, fontSize * 0.5, fontSize), color);
    }
#endif
}

Point BitmapRenderer::measureText(const std::string& text, float fontSize, bool bold) {
#ifdef HAS_STB_TRUETYPE
    if (!font_loaded || !font_info) {
        return Point(text.length() * fontSize * 0.6, fontSize);
    }
    
    stbtt_fontinfo* font = static_cast<stbtt_fontinfo*>(font_info);
    float scale = stbtt_ScaleForPixelHeight(font, fontSize);
    
    float width = 0;
    for (char c : text) {
        if (c < 32 || c > 126) continue;
        
        int advanceWidth, leftSideBearing;
        stbtt_GetCodepointHMetrics(font, c, &advanceWidth, &leftSideBearing);
        width += advanceWidth * scale;
    }
    
    int ascent, descent, lineGap;
    stbtt_GetFontVMetrics(font, &ascent, &descent, &lineGap);
    float height = (ascent - descent) * scale;
    
    return Point(width, height);
#else
    return Point(text.length() * fontSize * 0.6, fontSize);
#endif
}

bool BitmapRenderer::savePNG(const std::string& filename) {
#ifdef HAS_STB_IMAGE_WRITE
    return stbi_write_png(filename.c_str(), width, height, 4, pixels.data(), width * 4) != 0;
#else
    return false;
#endif
}