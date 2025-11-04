
import time
from datetime import datetime
import argparse
import os
import torch
import cv2
from configs import load_config
from modules.awl_detector import pred_rcnn, vis, find_element_type
from modules.logo_matching import check_domain_brand_inconsistency
from modules.crp_classifier import credential_classifier_mixed, html_heuristic
from modules.crp_locator import crp_locator
from modules.url_analyzer import URLAnalyzer, quick_url_check
from utils.web_utils import driver_loader
from tqdm import tqdm
import re
# from memory_profiler import profile

os.environ['KMP_DUPLICATE_LIB_OK']='True'

class PhishIntentionWrapper:
    _caller_prefix = "PhishIntentionWrapper"
    _DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'

    def __init__(self, enable_url_analysis=True, enable_visual_analysis=True):
        self.enable_url_analysis = enable_url_analysis
        self.enable_visual_analysis = enable_visual_analysis
        
        # Only load visual models if visual analysis is enabled
        if self.enable_visual_analysis:
            self._load_config()
        
        # Initialize URL analyzer if enabled
        if self.enable_url_analysis:
            self.url_analyzer = URLAnalyzer(timeout=5)
            print("URL Analysis module enabled")

    def _load_config(self):
        self.AWL_MODEL, self.CRP_CLASSIFIER, self.CRP_LOCATOR_MODEL, self.SIAMESE_MODEL, self.OCR_MODEL, \
            self.SIAMESE_THRE, self.LOGO_FEATS, self.LOGO_FILES, self.DOMAIN_MAP_PATH = load_config()
        print(f'Length of reference list = {len(self.LOGO_FEATS)}')

    '''PhishIntention'''
    def test_orig_phishintention(self, url, screenshot_path):

        waive_crp_classifier = False
        phish_category = 0  # 0 for benign, 1 for phish, default is benign
        pred_target = None
        matched_domain = None
        siamese_conf = None
        awl_detect_time = 0
        logo_match_time = 0
        crp_class_time = 0
        crp_locator_time = 0
        url_analysis_time = 0
        url_risk_score = 0.0
        url_features = {}
        url_indicates_phishing = False
        
        print("Entering PhishIntention")
        
        ####################### Step 0: URL Analysis (ALWAYS RUNS FIRST) ##############################################
        if self.enable_url_analysis:
            print("Step 0: Performing URL analysis...")
            start_time = time.time()
            try:
                url_features = self.url_analyzer.analyze(url)
                url_risk_score = url_features.get('risk_score', 0.0)
                url_analysis_time = time.time() - start_time
                print(f"URL Risk Score: {url_risk_score:.3f} ({url_features.get('risk_level', 'unknown')})")
                
                # Mark if URL indicates phishing, but continue with visual detection
                if url_risk_score >= 0.7:
                    url_indicates_phishing = True
                    print("⚠️ WARNING: URL analysis indicates HIGH RISK!")
                    print("➡️ Continuing with visual detection for comprehensive analysis...")
                elif url_risk_score >= 0.5:
                    print("⚠️ CAUTION: URL shows moderate risk")
                    print("➡️ Continuing with visual detection...")
                else:
                    print("✅ URL appears safe")
                    print("➡️ Continuing with visual detection for confirmation...")
            except (ValueError, KeyError, TypeError) as e:
                print(f"URL analysis error: {e}")
                url_analysis_time = time.time() - start_time
            except Exception as e:
                print(f"Unexpected error in URL analysis: {e}")
                url_analysis_time = time.time() - start_time
        
        print("\n" + "="*70)
        print("Starting Visual Detection (Logo + CRP Analysis)...")
        print("="*70)

        while True:

            ####################### Step1: Layout detector ##############################################
            start_time = time.time()
            pred_boxes, pred_classes, _ = pred_rcnn(im=screenshot_path, predictor=self.AWL_MODEL)
            awl_detect_time += time.time() - start_time

            if pred_boxes is not None:
                pred_boxes = pred_boxes.numpy()
                pred_classes = pred_classes.numpy()
            plotvis = vis(screenshot_path, pred_boxes, pred_classes)

            # If no element is reported
            if pred_boxes is None or len(pred_boxes) == 0:
                print('No element is detected')
                # Decision fusion: URL + Visual
                if url_indicates_phishing:
                    print('⚠️ PHISHING detected by URL analysis (no visual elements found)')
                    phish_category = 1
                    pred_target = 'URL-based detection'
                else:
                    print('✅ Reported as benign (no visual elements + safe URL)')
                return phish_category, pred_target, matched_domain, plotvis, siamese_conf, \
                            str(awl_detect_time) + '|' + str(logo_match_time) + '|' + str(crp_class_time) + '|' + str(crp_locator_time) + '|' + str(url_analysis_time), \
                            pred_boxes, pred_classes, url_risk_score, url_features

            logo_pred_boxes, _ = find_element_type(pred_boxes, pred_classes, bbox_type='logo')
            if logo_pred_boxes is None or len(logo_pred_boxes) == 0:
                print('No logo is detected')
                # Decision fusion: URL + Visual
                if url_indicates_phishing:
                    print('⚠️ PHISHING detected by URL analysis (no logo found)')
                    phish_category = 1
                    pred_target = 'URL-based detection'
                else:
                    print('✅ Reported as benign (no logo + safe URL)')
                return phish_category, pred_target, matched_domain, plotvis, siamese_conf, \
                            str(awl_detect_time) + '|' + str(logo_match_time) + '|' + str(crp_class_time) + '|' + str(crp_locator_time) + '|' + str(url_analysis_time), \
                            pred_boxes, pred_classes, url_risk_score, url_features

            print('Entering siamese')

            ######################## Step2: Siamese (Logo matcher) ########################################
            start_time = time.time()
            pred_target, matched_domain, matched_coord, siamese_conf = check_domain_brand_inconsistency(logo_boxes=logo_pred_boxes,
                                                                                      domain_map_path=self.DOMAIN_MAP_PATH,
                                                                                      model = self.SIAMESE_MODEL,
                                                                                      ocr_model = self.OCR_MODEL,
                                                                                      logo_feat_list = self.LOGO_FEATS,
                                                                                      file_name_list = self.LOGO_FILES,
                                                                                      url=url,
                                                                                      shot_path=screenshot_path,
                                                                                      ts=self.SIAMESE_THRE)
            logo_match_time += time.time() - start_time

            if pred_target is None:
                print('Did not match to any brand')
                # Decision fusion: URL + Visual
                if url_indicates_phishing:
                    print('⚠️ PHISHING detected by URL analysis (no brand match in visual)')
                    phish_category = 1
                    pred_target = 'URL-based detection (suspicious URL patterns)'
                else:
                    print('✅ Reported as benign (no brand match + safe URL)')
                return phish_category, pred_target, matched_domain, plotvis, siamese_conf, \
                            str(awl_detect_time) + '|' + str(logo_match_time) + '|' + str(crp_class_time) + '|' + str(crp_locator_time) + '|' + str(url_analysis_time), \
                            pred_boxes, pred_classes, url_risk_score, url_features

            ######################## Step3: CRP classifier (if a target is reported) #################################
            print('A target is reported by siamese, enter CRP classifier')
            if waive_crp_classifier:  # only run dynamic analysis ONCE
                break

            # Get html.txt path from folder, not by string replacement
            folder_path = os.path.dirname(screenshot_path)
            html_path = os.path.join(folder_path, "html.txt")
            start_time = time.time()
            cre_pred = html_heuristic(html_path)
            if cre_pred == 1:  # if HTML heuristic report as nonCRP
                # CRP classifier
                cre_pred = credential_classifier_mixed(img=screenshot_path,
                                                         coords=pred_boxes,
                                                         types=pred_classes,
                                                         model=self.CRP_CLASSIFIER)
            crp_class_time += time.time() - start_time

            ######################## Step4: Dynamic analysis #################################
            if cre_pred == 1:
                print('It is a Non-CRP page, enter dynamic analysis')
                # # load driver ONCE!
                driver = driver_loader()
                print('Finish loading webdriver')
                # load chromedriver
                url, screenshot_path, successful, process_time = crp_locator(url=url,
                                                                             screenshot_path=screenshot_path,
                                                                             cls_model=self.CRP_CLASSIFIER,
                                                                             ele_model=self.AWL_MODEL,
                                                                             login_model=self.CRP_LOCATOR_MODEL,
                                                                             driver=driver)
                crp_locator_time += process_time
                try:
                    driver.quit()
                except Exception as e:
                    print(f"Warning: Failed to close driver: {e}")

                waive_crp_classifier = True  # only run dynamic analysis ONCE

                # If dynamic analysis did not reach a CRP
                if not successful:
                    print('Dynamic analysis cannot find any link redirected to a CRP page')
                    # Decision fusion: URL + Visual
                    if url_indicates_phishing and pred_target is not None:
                        print('⚠️ PHISHING detected: High-risk URL + Brand detected (even without CRP)')
                        phish_category = 1
                        # Continue to add visualization
                    else:
                        print('✅ Reported as benign (no CRP found)')
                        return phish_category, pred_target, matched_domain, plotvis, siamese_conf, \
                                str(awl_detect_time) + '|' + str(logo_match_time) + '|' + str(crp_class_time) + '|' + str(crp_locator_time) + '|' + str(url_analysis_time), \
                                pred_boxes, pred_classes, url_risk_score, url_features

                else:  # dynamic analysis successfully found a CRP
                    print('Dynamic analysis found a CRP, go back to layout detector')

            else:  # already a CRP page
                print('Already a CRP, continue')
                break

        ######################## Step5: Return #################################
        if pred_target is not None:
            print('\n' + '='*70)
            print('FINAL DECISION: Phishing Detection Results')
            print('='*70)
            phish_category = 1
            
            # Enhanced decision with fusion confidence
            conf_str = f"{siamese_conf:.4f}" if siamese_conf is not None else "N/A"
            if url_indicates_phishing:
                print(f'✓ Visual Detection: PHISHING (Brand: {pred_target}, Confidence: {conf_str})')
                print(f'✓ URL Detection: HIGH RISK (Score: {url_risk_score:.3f})')
                print('🎯 FUSION RESULT: HIGH CONFIDENCE PHISHING')
                fusion_confidence = min((siamese_conf if siamese_conf is not None else 0.5) + (url_risk_score * 0.3), 1.0)
            else:
                print(f'✓ Visual Detection: PHISHING (Brand: {pred_target}, Confidence: {conf_str})')
                print(f'✓ URL Detection: Low/Medium Risk (Score: {url_risk_score:.3f})')
                print('⚠️ FUSION RESULT: PHISHING (Visual evidence strong)')
                fusion_confidence = siamese_conf if siamese_conf is not None else 0.5
            
            # Visualize, add annotations (with null checks)
            if plotvis is not None and matched_coord is not None:
                cv2.putText(plotvis, "Target: {} (Conf: {:.4f})".format(pred_target, fusion_confidence),
                            (int(matched_coord[0] + 20), int(matched_coord[1] + 20)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 0), 2)
                
                # Add URL risk info to visualization
                if self.enable_url_analysis and url_risk_score > 0:
                    risk_color = (0, 0, 255) if url_risk_score >= 0.7 else (0, 165, 255) if url_risk_score >= 0.5 else (0, 255, 0)
                    cv2.putText(plotvis, "URL Risk: {:.2f}".format(url_risk_score),
                                (int(matched_coord[0] + 20), int(matched_coord[1] + 50)),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.7, risk_color, 2)
            
            print('='*70)
        elif url_indicates_phishing:
            # URL detected phishing but visual didn't - rare case
            print('\n' + '='*70)
            print('⚠️ URL-ONLY PHISHING DETECTION')
            print('='*70)
            print('URL shows high-risk patterns but no visual phishing indicators found')
            print('This could be a phishing attempt or false positive')
            print('='*70)

        return phish_category, pred_target, matched_domain, plotvis, siamese_conf, \
                    str(awl_detect_time) + '|' + str(logo_match_time) + '|' + str(crp_class_time) + '|' + str(crp_locator_time) + '|' + str(url_analysis_time), \
                    pred_boxes, pred_classes, url_risk_score, url_features

if __name__ == '__main__':

    '''run'''
    today = datetime.now().strftime('%Y%m%d')

    parser = argparse.ArgumentParser(
        description='PhishFusion-Net: Multi-Modal Phishing Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Visual-only mode (no URL analysis)
  python phishintention.py --folder datasets/legitimacy_3049/0.paulchen3.club --mode visual
  
  # URL-only mode (fast, for batch processing use batch_url_analysis.py instead)
  python phishintention.py --folder datasets/legitimacy_3049/0.paulchen3.club --mode url
  
  # Fusion mode (both URL and Visual - most accurate)
  python phishintention.py --folder datasets/legitimacy_3049/0.paulchen3.club --mode fusion
  
  # Batch analysis
  python phishintention.py --folder datasets/legitimacy_3049 --mode fusion --output_txt results.txt
        """
    )
    parser.add_argument("--folder", required=True, type=str, 
                        help="Path to folder containing sites (each with shot.png and info.txt)")
    parser.add_argument("--output_txt", default=f'{today}_results.txt', 
                        help="Output txt path (default: YYYYMMDD_results.txt)")
    parser.add_argument("--mode", type=str, default='fusion', 
                        choices=['visual', 'url', 'fusion'],
                        help="Analysis mode: 'visual' (visual only), 'url' (URL only - not recommended for batch), 'fusion' (both - default)")
    args = parser.parse_args()

    request_dir = args.folder
    
    # Initialize detector based on mode
    if args.mode == 'visual':
        print("="*70)
        print("Mode: VISUAL-ONLY Analysis")
        print("URL analysis is DISABLED")
        print("="*70)
        phishintention_cls = PhishIntentionWrapper(enable_url_analysis=False, enable_visual_analysis=True)
    elif args.mode == 'url':
        print("="*70)
        print("Mode: URL-ONLY Analysis")
        print("⚠️  Warning: For batch URL analysis, use batch_url_analysis.py instead!")
        print("Visual analysis is DISABLED (models not loaded)")
        print("="*70)
        # URL-only mode - don't load visual models to save memory
        phishintention_cls = PhishIntentionWrapper(enable_url_analysis=True, enable_visual_analysis=False)
    else:  # fusion
        print("="*70)
        print("Mode: PHISHFUSION (URL + Visual)")
        print("Both URL and Visual analysis ENABLED")
        print("="*70)
        phishintention_cls = PhishIntentionWrapper(enable_url_analysis=True, enable_visual_analysis=True)
    
    result_txt = args.output_txt

    os.makedirs(request_dir, exist_ok=True)

    # Load already processed URLs into a set for O(1) lookup (performance optimization)
    processed_urls = set()
    if os.path.exists(result_txt):
        try:
            with open(result_txt, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) > 1:
                        processed_urls.add(parts[1])  # URL is second column
        except UnicodeDecodeError:
            # Fallback to ISO-8859-1 for legacy files
            with open(result_txt, 'r', encoding='ISO-8859-1') as f:
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) > 1:
                        processed_urls.add(parts[1])
        except Exception as e:
            print(f"Warning: Could not load processed URLs: {e}")
    
    print(f"Loaded {len(processed_urls)} already processed URLs")

    # Check if request_dir is a single site folder or contains multiple sites
    is_single_site = os.path.exists(os.path.join(request_dir, "shot.png")) or \
                     os.path.exists(os.path.join(request_dir, "info.txt"))
    
    if is_single_site:
        # Single site mode
        folders_to_process = [os.path.basename(request_dir)]
        base_dir = os.path.dirname(request_dir)
        if not base_dir:
            base_dir = '.'
    else:
        # Batch mode
        folders_to_process = os.listdir(request_dir)
        base_dir = request_dir

    # Progress bar with better description
    total_sites = len(folders_to_process)
    skipped = 0
    processed = 0
    errors = 0
    
    site_word = "site" if total_sites == 1 else "sites"
    pbar = tqdm(folders_to_process, desc=f"Processing {total_sites} {site_word}", unit="site")
    
    for folder in pbar:
        if is_single_site:
            folder_path = request_dir
            folder_name = folder
        else:
            folder_path = os.path.join(request_dir, folder)
            folder_name = folder
        
        html_path = os.path.join(folder_path, "html.txt")
        screenshot_path = os.path.join(folder_path, "shot.png")
        info_path = os.path.join(folder_path, 'info.txt')

        # For URL-only mode, we don't need screenshot
        if args.mode != 'url' and not os.path.exists(screenshot_path):
            pbar.set_postfix_str(f"⏭️ Skip: no screenshot")
            skipped += 1
            continue
        
        # For visual modes, we need screenshot
        if args.mode == 'visual' and not os.path.exists(screenshot_path):
            pbar.set_postfix_str(f"⏭️ Skip: screenshot required")
            skipped += 1
            continue

        if os.path.exists(info_path):
            with open(info_path, 'r', encoding='utf-8') as f:
                url = f.read().strip()
        else:
            url = "https://" + folder_name

        # Check if already processed - O(1) set lookup instead of O(n) file read
        if url in processed_urls:
            pbar.set_postfix_str(f"⏭️ Already processed")
            skipped += 1
            continue

        _forbidden_suffixes = r"\.(mp3|wav|wma|ogg|mkv|zip|tar|xz|rar|z|deb|bin|iso|csv|tsv|dat|txt|css|log|sql|xml|sql|mdb|apk|bat|bin|exe|jar|wsf|fnt|fon|otf|ttf|ai|bmp|gif|ico|jp(e)?g|png|ps|psd|svg|tif|tiff|cer|rss|key|odp|pps|ppt|pptx|c|class|cpp|cs|h|java|sh|swift|vb|odf|xlr|xls|xlsx|bak|cab|cfg|cpl|cur|dll|dmp|drv|icns|ini|lnk|msi|sys|tmp|3g2|3gp|avi|flv|h264|m4v|mov|mp4|mp(e)?g|rm|swf|vob|wmv|doc(x)?|odt|rtf|tex|txt|wks|wps|wpd)$"
        if re.search(_forbidden_suffixes, url, re.IGNORECASE):
            pbar.set_postfix_str(f"⏭️ Skip: forbidden file type")
            skipped += 1
            continue
        
        # Update progress bar with current URL
        url_display = url[:50] + "..." if len(url) > 50 else url
        pbar.set_description(f"Processing: {url_display}")

        # Process based on mode - unified approach
        try:
            if args.mode == 'url':
                # URL-only mode: Use a lightweight wrapper method
                pbar.set_postfix_str("🔍 Analyzing URL...")
                
                start_time = time.time()
                url_features = phishintention_cls.url_analyzer.analyze(url)
                url_analysis_time = time.time() - start_time
                
                url_risk_score = url_features.get('risk_score', 0.0)
                url_risk_level = url_features.get('risk_level', 'unknown')
                
                # For URL-only mode, set visual results to N/A
                phish_category = 1 if url_risk_score > 0.7 else 0
                pred_target = 'N/A (URL-only mode)'
                matched_domain = 'N/A'
                siamese_conf = 0.0
                runtime_breakdown = f"0|0|0|0|{url_analysis_time:.4f}"
                
                risk_emoji = "🚨" if url_risk_score >= 0.7 else "⚠️" if url_risk_score >= 0.5 else "✅"
                pbar.set_postfix_str(f"{risk_emoji} Risk: {url_risk_score:.2f}")
                
            else:
                # Visual or Fusion mode
                pbar.set_postfix_str("🔍 Running detection...")
                
                phish_category, pred_target, matched_domain, \
                        plotvis, siamese_conf, runtime_breakdown, \
                        pred_boxes, pred_classes, url_risk_score, url_features = \
                        phishintention_cls.test_orig_phishintention(url, screenshot_path)
                
                url_risk_level = url_features.get('risk_level', 'unknown') if url_features else 'N/A'
                
                result_emoji = "🚨 PHISHING" if phish_category == 1 else "✅ BENIGN"
                pbar.set_postfix_str(result_emoji)
                
                # Save visualization if phishing detected
                if phish_category and plotvis is not None:
                    os.makedirs(folder_path, exist_ok=True)
                    cv2.imwrite(os.path.join(folder_path, "predict.png"), plotvis)
            
            # Write results with consistent UTF-8 encoding (unified for all modes)
            with open(result_txt, "a+", encoding='utf-8') as f:
                f.write(folder_name + "\t")
                f.write(url + "\t")
                f.write(str(phish_category) + "\t")
                f.write(str(pred_target) + "\t")
                f.write(str(matched_domain) + "\t")
                f.write(str(siamese_conf) + "\t")
                f.write(str(url_risk_score) + "\t")
                f.write(str(url_risk_level) + "\t")
                f.write(runtime_breakdown + "\n")
            
            # Add to processed set
            processed_urls.add(url)
            processed += 1
                
        except Exception as e:
            pbar.set_postfix_str(f"❌ Error")
            errors += 1
            print(f"\n❌ Error analyzing {folder_name}: {str(e)}")
        
        # Break after first iteration if single site
        if is_single_site:
            break
    
    # Final summary
    print(f"\n{'='*70}")
    print(f"Analysis complete!")
    print(f"{'='*70}")
    print(f"✅ Processed: {processed}")
    print(f"⏭️  Skipped: {skipped}")
    if errors > 0:
        print(f"❌ Errors: {errors}")
    print(f"📁 Results saved to: {result_txt}")
    print(f"{'='*70}")
